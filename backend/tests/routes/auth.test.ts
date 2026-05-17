/**
 * auth.test.ts — Integration tests for /auth/* endpoints
 *
 * Mocks:
 *  - ../src/lib/db        → col() returns fake collection methods
 *  - ../src/lib/redis     → redisGet/redisSet/redisDel
 *  - ../src/services/email → sendEmail, sendPasswordResetEmail
 *  - ../src/lib/audit     → auditFromReq (no-op)
 *  - ../src/middlewares/rate-limit → authLimiter (pass-through)
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import express from "express";
import session from "express-session";
import supertest from "supertest";
import { ObjectId } from "mongodb";
import bcrypt from "bcryptjs";

// ── Shared test fixtures ──────────────────────────────────────────────────────

const USER_ID = new ObjectId().toHexString();
const HASHED_CORRECT = await bcrypt.hash("CorrectP@ss1", 10);

const mockUser = {
  _id: new ObjectId(USER_ID),
  username: "test_user",
  email: "test@example.com",
  password: HASHED_CORRECT,
  role: "analyst",
  first_name: "Test",
  last_name: "User",
  email_verified: false,
  two_fa_enabled: false,
};

// ── Mocks ─────────────────────────────────────────────────────────────────────

vi.mock("../../src/lib/db", () => ({
  col: vi.fn((name: string) => {
    if (name === "users") {
      return {
        findOne: vi.fn().mockResolvedValue(mockUser),
        find: vi.fn().mockReturnValue({
          sort: vi.fn().mockReturnValue({
            toArray: vi.fn().mockResolvedValue([mockUser]),
          }),
        }),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
        countDocuments: vi.fn().mockResolvedValue(0),
        aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
      };
    }
    if (name === "sessions") {
      return {
        findOne: vi.fn().mockResolvedValue(null),
        countDocuments: vi.fn().mockResolvedValue(0),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
        deleteMany: vi.fn().mockResolvedValue({ deletedCount: 0 }),
      };
    }
    if (name === "password_resets") {
      return {
        findOne: vi.fn().mockResolvedValue({
          _id: new ObjectId(),
          user_id: new ObjectId(USER_ID),
          token: "valid-reset-token",
          expires: new Date(Date.now() + 3_600_000),
          used: false,
        }),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
      };
    }
    if (name === "magic_links") {
      return {
        findOne: vi.fn().mockResolvedValue({
          _id: new ObjectId(),
          email: "test@example.com",
          token: "valid-magic-token",
          expires: new Date(Date.now() + 900_000),
          used: false,
        }),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
      };
    }
    if (name === "platform_policy") {
      return { findOne: vi.fn().mockResolvedValue(null) };
    }
    // Catch-all for audit_log, findings, scan_jobs, etc.
    return {
      findOne: vi.fn().mockResolvedValue(null),
      find: vi.fn().mockReturnValue({
        sort: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
      }),
      insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
      updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
      updateMany: vi.fn().mockResolvedValue({ modifiedCount: 0 }),
      deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
      deleteMany: vi.fn().mockResolvedValue({ deletedCount: 0 }),
      countDocuments: vi.fn().mockResolvedValue(0),
      aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
    };
  }),
  ObjectId,
}));

vi.mock("../../src/lib/redis", () => ({
  redisGet: vi.fn().mockResolvedValue(null),
  redisSet: vi.fn().mockResolvedValue("OK"),
  redisDel: vi.fn().mockResolvedValue(1),
  getRedis: vi.fn().mockReturnValue({
    set: vi.fn().mockResolvedValue("OK"),
    get: vi.fn().mockResolvedValue(null),
    del: vi.fn().mockResolvedValue(1),
  }),
}));

vi.mock("../../src/services/email", () => ({
  sendEmail: vi.fn().mockResolvedValue({ ok: true }),
  sendPasswordResetEmail: vi.fn().mockResolvedValue({ ok: true }),
}));

vi.mock("../../src/lib/audit", () => ({
  auditFromReq: vi.fn().mockResolvedValue(undefined),
  logAudit: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../../src/middlewares/rate-limit", () => ({
  authLimiter: (_req: unknown, _res: unknown, next: () => void) => next(),
  globalLimiter: (_req: unknown, _res: unknown, next: () => void) => next(),
}));

// ── Build test app ─────────────────────────────────────────────────────────────

async function buildApp() {
  const app = express();
  app.use(express.json());
  app.use(
    session({
      secret: "test-secret-at-least-32-chars-long!",
      resave: false,
      saveUninitialized: false,
      name: "bbp.sid",
    })
  );

  const { default: authRouter } = await import("../../src/routes/auth");
  app.use("/api", authRouter);
  return app;
}

// ── Helper: authenticated agent ───────────────────────────────────────────────

async function authedAgent(app: Awaited<ReturnType<typeof buildApp>>) {
  const agent = supertest.agent(app);
  // Manually forge a session via the demo endpoint (no DB write needed for login path)
  // Use POST /api/auth/demo which auto-creates admin and sets session
  await agent.post("/api/auth/demo");
  return agent;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test suites
// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/auth/register", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    // For register: users.findOne returns null (no duplicate) by default
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "users") {
        return {
          findOne: vi.fn().mockResolvedValue(null),
          insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        } as never;
      }
      return {
        findOne: vi.fn().mockResolvedValue(null),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
        countDocuments: vi.fn().mockResolvedValue(0),
        find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }),
        aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
      } as never;
    });
    app = await buildApp();
  });

  it("returns 201 with valid registration data", async () => {
    const res = await supertest(app).post("/api/auth/register").send({
      firstName: "Jane",
      lastName: "Doe",
      email: "jane@example.com",
      password: "StrongP@ss123",
    });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty("id");
    expect(res.body.role).toBe("analyst");
    expect(res.body.email).toBe("jane@example.com");
  });

  it("returns 400 when password is shorter than 12 chars", async () => {
    const res = await supertest(app).post("/api/auth/register").send({
      firstName: "Jane",
      lastName: "Doe",
      email: "jane2@example.com",
      password: "Short1!",
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/12 characters/i);
  });

  it("returns 400 when password lacks uppercase letter", async () => {
    const res = await supertest(app).post("/api/auth/register").send({
      firstName: "Jane",
      lastName: "Doe",
      email: "jane3@example.com",
      password: "nouppercase123!",
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/uppercase/i);
  });

  it("returns 400 when password lacks a number", async () => {
    const res = await supertest(app).post("/api/auth/register").send({
      firstName: "Jane",
      lastName: "Doe",
      email: "jane4@example.com",
      password: "NoNumbers!!!!",
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/number/i);
  });

  it("returns 400 when password lacks special character", async () => {
    const res = await supertest(app).post("/api/auth/register").send({
      firstName: "Jane",
      lastName: "Doe",
      email: "jane5@example.com",
      password: "NoSpecialChar1",
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/special character/i);
  });

  it("returns 400 when required fields are missing", async () => {
    const res = await supertest(app).post("/api/auth/register").send({});
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("returns 409 when email is already registered", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "users") {
        return {
          findOne: vi.fn().mockResolvedValue(mockUser), // duplicate found
          insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        } as never;
      }
      return {
        findOne: vi.fn().mockResolvedValue(null),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
        countDocuments: vi.fn().mockResolvedValue(0),
        find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }),
        aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
      } as never;
    });
    const dupApp = await buildApp();
    const res = await supertest(dupApp).post("/api/auth/register").send({
      firstName: "Jane",
      lastName: "Doe",
      email: "test@example.com",
      password: "StrongP@ss123",
    });
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/already exists/i);
  });

  it("returns 400 when only some fields are supplied", async () => {
    const res = await supertest(app).post("/api/auth/register").send({
      firstName: "Jane",
    });
    expect(res.status).toBe(400);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/auth/login", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "users") {
        return {
          findOne: vi.fn().mockResolvedValue(mockUser),
          insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
          updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        } as never;
      }
      return {
        findOne: vi.fn().mockResolvedValue(null),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        updateMany: vi.fn().mockResolvedValue({ modifiedCount: 0 }),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
        deleteMany: vi.fn().mockResolvedValue({ deletedCount: 0 }),
        countDocuments: vi.fn().mockResolvedValue(0),
        find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }),
        aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
      } as never;
    });
    app = await buildApp();
  });

  it("returns 200 and user info with valid credentials", async () => {
    const res = await supertest(app).post("/api/auth/login").send({
      email: "test@example.com",
      password: "CorrectP@ss1",
    });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("id");
    expect(res.body).toHaveProperty("username");
    expect(res.body).toHaveProperty("email");
    expect(res.body).toHaveProperty("role");
  });

  it("returns 401 with wrong password", async () => {
    const res = await supertest(app).post("/api/auth/login").send({
      email: "test@example.com",
      password: "WrongPassword999!",
    });
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/invalid credentials/i);
  });

  it("returns 401 when user does not exist", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "users") {
        return { findOne: vi.fn().mockResolvedValue(null), insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }) } as never;
      }
      return {
        findOne: vi.fn().mockResolvedValue(null),
        countDocuments: vi.fn().mockResolvedValue(0),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 0 }),
      } as never;
    });
    const noUserApp = await buildApp();
    const res = await supertest(noUserApp).post("/api/auth/login").send({
      email: "nobody@example.com",
      password: "AnyPassword123!",
    });
    expect(res.status).toBe(401);
  });

  it("returns 400 when email is missing", async () => {
    const res = await supertest(app).post("/api/auth/login").send({ password: "SomePass123!" });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("returns 400 when password is missing", async () => {
    const res = await supertest(app).post("/api/auth/login").send({ email: "test@example.com" });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("returns 400 when body is empty", async () => {
    const res = await supertest(app).post("/api/auth/login").send({});
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("returns 429 when Redis lockout is active (>= 5 failed attempts)", async () => {
    const { redisGet } = await import("../../src/lib/redis");
    vi.mocked(redisGet).mockResolvedValueOnce("5"); // lockout value
    const res = await supertest(app).post("/api/auth/login").send({
      email: "locked@example.com",
      password: "AnyPass123!",
    });
    expect(res.status).toBe(429);
    expect(res.body.error).toMatch(/locked/i);
  });

  it("returns 403 when user role requires MFA but totp_enabled is false", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "users") {
        return {
          findOne: vi.fn()
            .mockResolvedValueOnce({ ...mockUser, role: "admin" })    // first call: auth lookup
            .mockResolvedValueOnce({ ...mockUser, role: "admin", totp_enabled: false }), // second call: full user
          insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
          updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        } as never;
      }
      if (name === "sessions") {
        return { countDocuments: vi.fn().mockResolvedValue(0), deleteOne: vi.fn().mockResolvedValue({ deletedCount: 0 }) } as never;
      }
      if (name === "platform_policy") {
        return { findOne: vi.fn().mockResolvedValue({ require_mfa_roles: ["admin"], mfa_grace_days: 0 }) } as never;
      }
      return {
        findOne: vi.fn().mockResolvedValue(null),
        countDocuments: vi.fn().mockResolvedValue(0),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 0 }),
      } as never;
    });
    const mfaApp = await buildApp();
    const res = await supertest(mfaApp).post("/api/auth/login").send({
      email: "test@example.com",
      password: "CorrectP@ss1",
    });
    expect(res.status).toBe(403);
    expect(res.body).toHaveProperty("mfa_required");
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/auth/logout", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    app = await buildApp();
  });

  it("returns 200 and clears session cookie", async () => {
    const agent = supertest.agent(app);
    // Inject session via demo endpoint
    await agent.post("/api/auth/demo");
    const res = await agent.post("/api/auth/logout");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });

  it("returns 200 even without an active session (idempotent)", async () => {
    const res = await supertest(app).post("/api/auth/logout");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("GET /api/auth/me", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "users") {
        return { findOne: vi.fn().mockResolvedValue(mockUser) } as never;
      }
      return {
        findOne: vi.fn().mockResolvedValue(null),
        countDocuments: vi.fn().mockResolvedValue(0),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 0 }),
      } as never;
    });
    app = await buildApp();
  });

  it("returns 401 when not authenticated", async () => {
    const res = await supertest(app).get("/api/auth/me");
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty("error");
  });

  it("returns user profile when authenticated", async () => {
    const agent = supertest.agent(app);
    await agent.post("/api/auth/demo");
    const res = await agent.get("/api/auth/me");
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("id");
    expect(res.body).toHaveProperty("username");
    expect(res.body).toHaveProperty("email");
    expect(res.body).toHaveProperty("role");
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/auth/forgot-password", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    app = await buildApp();
  });

  it("returns 200 for a valid email (security: no enumeration)", async () => {
    const res = await supertest(app).post("/api/auth/forgot-password").send({
      email: "test@example.com",
    });
    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/reset link/i);
  });

  it("returns 200 for a non-existent email (prevents user enumeration)", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "users") return { findOne: vi.fn().mockResolvedValue(null) } as never;
      return {
        findOne: vi.fn().mockResolvedValue(null),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
      } as never;
    });
    const noUserApp = await buildApp();
    const res = await supertest(noUserApp).post("/api/auth/forgot-password").send({
      email: "nobody@example.com",
    });
    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/reset link/i);
  });

  it("returns 400 when email field is missing", async () => {
    const res = await supertest(app).post("/api/auth/forgot-password").send({});
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/auth/reset-password", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "users") {
        return {
          findOne: vi.fn().mockResolvedValue(mockUser),
          updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
          insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        } as never;
      }
      if (name === "password_resets") {
        return {
          findOne: vi.fn().mockResolvedValue({
            _id: new ObjectId(),
            user_id: new ObjectId(USER_ID),
            token: "valid-reset-token",
            expires: new Date(Date.now() + 3_600_000),
            used: false,
          }),
          insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
          updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        } as never;
      }
      return {
        findOne: vi.fn().mockResolvedValue(null),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        updateMany: vi.fn().mockResolvedValue({ modifiedCount: 0 }),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
        deleteMany: vi.fn().mockResolvedValue({ deletedCount: 0 }),
        countDocuments: vi.fn().mockResolvedValue(0),
        find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }),
        aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
      } as never;
    });
    app = await buildApp();
  });

  it("returns 200 and resets password with a valid token", async () => {
    const res = await supertest(app).post("/api/auth/reset-password").send({
      token: "valid-reset-token",
      password: "NewStrongP@ss1",
    });
    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/reset successfully/i);
  });

  it("returns 400 with an expired / invalid token", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "password_resets") {
        return {
          findOne: vi.fn().mockResolvedValue({
            _id: new ObjectId(),
            user_id: new ObjectId(),
            token: "expired-token",
            expires: new Date(Date.now() - 1000), // already expired
            used: false,
          }),
          updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        } as never;
      }
      return {
        findOne: vi.fn().mockResolvedValue(null),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        deleteMany: vi.fn().mockResolvedValue({ deletedCount: 0 }),
      } as never;
    });
    const expiredApp = await buildApp();
    const res = await supertest(expiredApp).post("/api/auth/reset-password").send({
      token: "expired-token",
      password: "NewStrongP@ss1",
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid or expired/i);
  });

  it("returns 400 when token is not found (null)", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "password_resets") {
        return { findOne: vi.fn().mockResolvedValue(null) } as never;
      }
      return { findOne: vi.fn().mockResolvedValue(null) } as never;
    });
    const noTokenApp = await buildApp();
    const res = await supertest(noTokenApp).post("/api/auth/reset-password").send({
      token: "not-a-real-token",
      password: "NewStrongP@ss1",
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid or expired/i);
  });

  it("returns 400 when token or password fields are missing", async () => {
    const res = await supertest(app).post("/api/auth/reset-password").send({});
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("returns 400 when new password is too short (< 6 chars)", async () => {
    const res = await supertest(app).post("/api/auth/reset-password").send({
      token: "valid-reset-token",
      password: "abc",
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/6 characters/i);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/auth/magic-link/request", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    app = await buildApp();
  });

  it("returns 200 for an existing email", async () => {
    const res = await supertest(app).post("/api/auth/magic-link/request").send({
      email: "test@example.com",
    });
    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/magic link/i);
  });

  it("returns 200 for non-existent email (prevents enumeration)", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "users") return { findOne: vi.fn().mockResolvedValue(null) } as never;
      return { findOne: vi.fn().mockResolvedValue(null), insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }) } as never;
    });
    const noUserApp = await buildApp();
    const res = await supertest(noUserApp).post("/api/auth/magic-link/request").send({
      email: "nobody@example.com",
    });
    expect(res.status).toBe(200);
  });

  it("returns 400 when email is missing", async () => {
    const res = await supertest(app).post("/api/auth/magic-link/request").send({});
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("GET /api/auth/magic-link/verify", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    app = await buildApp();
  });

  it("returns 400 when token query param is missing", async () => {
    const res = await supertest(app).get("/api/auth/magic-link/verify");
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/token/i);
  });

  it("returns 400 for an expired magic link", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "magic_links") {
        return {
          findOne: vi.fn().mockResolvedValue({
            _id: new ObjectId(),
            email: "test@example.com",
            token: "old-token",
            expires: new Date(Date.now() - 1000), // expired
            used: false,
          }),
          updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        } as never;
      }
      return { findOne: vi.fn().mockResolvedValue(null) } as never;
    });
    const expiredApp = await buildApp();
    const res = await supertest(expiredApp).get("/api/auth/magic-link/verify?token=old-token");
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid or expired/i);
  });

  it("returns 400 for a non-existent magic link", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "magic_links") {
        return { findOne: vi.fn().mockResolvedValue(null) } as never;
      }
      return { findOne: vi.fn().mockResolvedValue(null) } as never;
    });
    const noLinkApp = await buildApp();
    const res = await supertest(noLinkApp).get("/api/auth/magic-link/verify?token=bad-token");
    expect(res.status).toBe(400);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/auth/change-password", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "users") {
        return {
          findOne: vi.fn().mockResolvedValue(mockUser),
          updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
          insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        } as never;
      }
      return {
        findOne: vi.fn().mockResolvedValue(null),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        countDocuments: vi.fn().mockResolvedValue(0),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 0 }),
      } as never;
    });
    app = await buildApp();
  });

  it("returns 401 when not authenticated", async () => {
    const res = await supertest(app).post("/api/auth/change-password").send({
      currentPassword: "CorrectP@ss1",
      newPassword: "NewPass123!@#",
    });
    expect(res.status).toBe(401);
  });

  it("returns 400 when current password is incorrect", async () => {
    const agent = supertest.agent(app);
    await agent.post("/api/auth/demo");
    const res = await agent.post("/api/auth/change-password").send({
      currentPassword: "WrongOldPassword!",
      newPassword: "NewPass123!@#",
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/incorrect/i);
  });

  it("returns 200 when password change succeeds", async () => {
    const agent = supertest.agent(app);
    await agent.post("/api/auth/demo");
    const res = await agent.post("/api/auth/change-password").send({
      currentPassword: "CorrectP@ss1",
      newPassword: "NewPass123!@#",
    });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("ok", true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/auth/demo", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "users") {
        return {
          findOne: vi.fn().mockResolvedValue(null), // no existing admin, will create
          insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        } as never;
      }
      return {
        findOne: vi.fn().mockResolvedValue(null),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        countDocuments: vi.fn().mockResolvedValue(0),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 0 }),
      } as never;
    });
    app = await buildApp();
  });

  it("returns 200 with admin user data", async () => {
    const res = await supertest(app).post("/api/auth/demo");
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("id");
    expect(res.body).toHaveProperty("role");
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("GET /api/auth/2fa/status", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "users") {
        return {
          findOne: vi.fn().mockResolvedValue({ ...mockUser, two_fa_enabled: false }),
          insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        } as never;
      }
      return {
        findOne: vi.fn().mockResolvedValue(null),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        countDocuments: vi.fn().mockResolvedValue(0),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 0 }),
      } as never;
    });
    app = await buildApp();
  });

  it("returns 401 when not authenticated", async () => {
    const res = await supertest(app).get("/api/auth/2fa/status");
    expect(res.status).toBe(401);
  });

  it("returns 2FA enabled status when authenticated", async () => {
    const agent = supertest.agent(app);
    await agent.post("/api/auth/demo");
    const res = await agent.get("/api/auth/2fa/status");
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("enabled");
    expect(typeof res.body.enabled).toBe("boolean");
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("DELETE /api/auth/me (GDPR self-deletion)", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation(() => ({
      findOne: vi.fn().mockResolvedValue(mockUser),
      insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
      updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
      updateMany: vi.fn().mockResolvedValue({ modifiedCount: 0 }),
      deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
      deleteMany: vi.fn().mockResolvedValue({ deletedCount: 0 }),
      countDocuments: vi.fn().mockResolvedValue(0),
      find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }),
      aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
    } as never));
    app = await buildApp();
  });

  it("returns 401 when not authenticated", async () => {
    const res = await supertest(app).delete("/api/auth/me");
    expect(res.status).toBe(401);
  });

  it("returns 200 and deletes account when authenticated", async () => {
    const agent = supertest.agent(app);
    await agent.post("/api/auth/demo");
    const res = await agent.delete("/api/auth/me");
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("ok", true);
  });
});
