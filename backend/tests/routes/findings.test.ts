/**
 * findings.test.ts — Integration tests for /findings/* endpoints
 *
 * Mocks:
 *  - ../../src/lib/db
 *  - ../../src/lib/redis
 *  - ../../src/services/email
 *  - ../../src/lib/audit
 *  - ../../src/middlewares/rbac (requireAuth → pass-through with injected session)
 *  - ../../src/lib/pii-redact  → identity pass-through
 *  - ../../src/lib/compliance-map → returns []
 *  - ../../src/middlewares/resource-rbac → no scope filter
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import express from "express";
import session from "express-session";
import supertest from "supertest";
import { ObjectId } from "mongodb";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const FINDING_ID = new ObjectId();
const USER_ID = new ObjectId().toHexString();

const mockFinding = {
  _id: FINDING_ID,
  title: "SQL Injection",
  category: "Injection",
  severity: "critical",
  validation_status: "needs_review",
  confidence: 0.95,
  endpoint: "/api/users?id=1",
  description: "Parameterized queries not used",
  evidence: "Error-based SQLi confirmed",
  recommended_fix: "Use prepared statements",
  cvss_score: 9.8,
  cwe_id: "CWE-89",
  risk_score: 95,
  scanner_name: "sqli_scanner",
  created_at: new Date("2025-01-01"),
  target_url: "https://example.com",
  scan_job_id: new ObjectId(),
  user_id: USER_ID,
  status_history: [],
};

// ── Mocks ─────────────────────────────────────────────────────────────────────

vi.mock("../../src/lib/db", () => ({
  col: vi.fn((name: string) => {
    if (name === "findings") {
      return {
        findOne: vi.fn().mockResolvedValue(mockFinding),
        find: vi.fn().mockReturnValue({
          sort: vi.fn().mockReturnValue({
            skip: vi.fn().mockReturnValue({
              limit: vi.fn().mockReturnValue({
                toArray: vi.fn().mockResolvedValue([mockFinding]),
              }),
            }),
          }),
        }),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        updateMany: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
        deleteMany: vi.fn().mockResolvedValue({ deletedCount: 1 }),
        countDocuments: vi.fn().mockResolvedValue(1),
        aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
      };
    }
    if (name === "evidence_files") {
      return {
        findOne: vi.fn().mockResolvedValue(null),
        find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
      };
    }
    if (name === "fp_suppressions") {
      return {
        findOne: vi.fn().mockResolvedValue(null),
        find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
      };
    }
    if (name === "saved_filters") {
      return {
        find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
      };
    }
    if (name === "vuln_intel") {
      return { findOne: vi.fn().mockResolvedValue(null) };
    }
    if (name === "raw_evidence") {
      return { findOne: vi.fn().mockResolvedValue(null) };
    }
    if (name === "scan_jobs") {
      return {
        findOne: vi.fn().mockResolvedValue({ _id: new ObjectId(), target_url: "https://example.com", status: "completed", created_at: new Date("2024-12-01") }),
        find: vi.fn().mockReturnValue({
          sort: vi.fn().mockReturnValue({ limit: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }),
        }),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
      };
    }
    if (name === "users") {
      return {
        findOne: vi.fn().mockResolvedValue({ _id: new ObjectId(USER_ID), username: "test_user", email: "test@example.com", role: "analyst" }),
      };
    }
    // Catch-all
    return {
      findOne: vi.fn().mockResolvedValue(null),
      find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }),
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
  getRedis: vi.fn().mockReturnValue({ set: vi.fn(), get: vi.fn(), del: vi.fn() }),
}));

vi.mock("../../src/services/email", () => ({
  sendEmail: vi.fn().mockResolvedValue({ ok: true }),
  sendPasswordResetEmail: vi.fn().mockResolvedValue({ ok: true }),
}));

vi.mock("../../src/lib/audit", () => ({
  auditFromReq: vi.fn().mockResolvedValue(undefined),
  logAudit: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../../src/lib/pii-redact", () => ({
  redactObject: vi.fn((obj: unknown) => obj),
  FINDING_SENSITIVE_FIELDS: [],
}));

vi.mock("../../src/lib/compliance-map", () => ({
  getComplianceTags: vi.fn().mockReturnValue([]),
}));

vi.mock("../../src/middlewares/resource-rbac", () => ({
  engagementScopeFilter: vi.fn().mockReturnValue(null),
}));

// Dynamic imports inside routes (scanner, dedup, vuln-intel)
vi.mock("../../src/services/scanner/index", () => ({
  runScanPipeline: vi.fn().mockResolvedValue(undefined),
  scanEvents: { emit: vi.fn() },
  enqueueScan: vi.fn().mockResolvedValue({ ok: true }),
}));
vi.mock("../../src/services/dedup", () => ({
  clusterFindings: vi.fn().mockResolvedValue([]),
}));
vi.mock("../../src/services/vuln-intel", () => ({
  enrichFindingWithIntel: vi.fn().mockResolvedValue(undefined),
}));

// ── Build test app ─────────────────────────────────────────────────────────────

async function buildApp(role: "analyst" | "admin" = "analyst") {
  const app = express();
  app.use(express.json());
  app.use(
    session({
      secret: "test-secret-at-least-32-chars-long!",
      resave: false,
      saveUninitialized: false,
    })
  );

  // Inject session before route handler
  app.use((req, _res, next) => {
    const sess = req.session as Record<string, unknown>;
    sess["userId"] = USER_ID;
    sess["username"] = "test_user";
    sess["role"] = role;
    sess["created_at"] = Date.now();
    next();
  });

  const { default: findingsRouter } = await import("../../src/routes/findings");
  // Also need scans router for formatFinding import
  const { default: scansRouter } = await import("../../src/routes/scans");
  app.use("/api", scansRouter);
  app.use("/api", findingsRouter);
  return app;
}

async function buildUnauthApp() {
  const app = express();
  app.use(express.json());
  app.use(
    session({
      secret: "test-secret-at-least-32-chars-long!",
      resave: false,
      saveUninitialized: false,
    })
  );
  // No session injection — unauthenticated
  const { default: findingsRouter } = await import("../../src/routes/findings");
  app.use("/api", findingsRouter);
  return app;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test suites
// ─────────────────────────────────────────────────────────────────────────────

describe("GET /api/findings", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;
  let unauthApp: Awaited<ReturnType<typeof buildUnauthApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    app = await buildApp();
    unauthApp = await buildUnauthApp();
  });

  it("returns 401 when not authenticated", async () => {
    const res = await supertest(unauthApp).get("/api/findings");
    expect(res.status).toBe(401);
  });

  it("returns paginated findings list when authenticated", async () => {
    const res = await supertest(app).get("/api/findings");
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("items");
    expect(res.body).toHaveProperty("total");
    expect(res.body).toHaveProperty("page");
    expect(res.body).toHaveProperty("page_size");
    expect(Array.isArray(res.body.items)).toBe(true);
  });

  it("accepts page and page_size query params", async () => {
    const res = await supertest(app).get("/api/findings?page=2&page_size=5");
    expect(res.status).toBe(200);
    expect(res.body.page).toBe(2);
    expect(res.body.page_size).toBe(5);
  });

  it("filters by severity query param", async () => {
    const res = await supertest(app).get("/api/findings?severity=critical");
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("items");
  });

  it("filters by validation_status query param", async () => {
    const res = await supertest(app).get("/api/findings?validation_status=confirmed");
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("items");
  });

  it("handles search query param without error", async () => {
    const res = await supertest(app).get("/api/findings?search=injection");
    expect(res.status).toBe(200);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("GET /api/findings/:id", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;
  let unauthApp: Awaited<ReturnType<typeof buildUnauthApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    app = await buildApp();
    unauthApp = await buildUnauthApp();
  });

  it("returns 401 when not authenticated", async () => {
    const res = await supertest(unauthApp).get(`/api/findings/${FINDING_ID.toHexString()}`);
    expect(res.status).toBe(401);
  });

  it("returns finding data for a valid ObjectId", async () => {
    const res = await supertest(app).get(`/api/findings/${FINDING_ID.toHexString()}`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("id");
    expect(res.body).toHaveProperty("title");
    expect(res.body).toHaveProperty("severity");
  });

  it("returns 404 for an invalid (non-ObjectId) id", async () => {
    const res = await supertest(app).get("/api/findings/not-an-objectid");
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty("error");
  });

  it("returns 404 when finding does not exist", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "findings") return { findOne: vi.fn().mockResolvedValue(null) } as never;
      return { findOne: vi.fn().mockResolvedValue(null) } as never;
    });
    const noFindingApp = await buildApp();
    const res = await supertest(noFindingApp).get(`/api/findings/${new ObjectId().toHexString()}`);
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty("error");
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("PATCH /api/findings/:id", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;
  let unauthApp: Awaited<ReturnType<typeof buildUnauthApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "findings") {
        return {
          findOne: vi.fn().mockResolvedValue(mockFinding),
          find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ skip: vi.fn().mockReturnValue({ limit: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([mockFinding]) }) }) }) }),
          insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
          updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
          updateMany: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
          deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
          deleteMany: vi.fn().mockResolvedValue({ deletedCount: 1 }),
          countDocuments: vi.fn().mockResolvedValue(1),
          aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
        } as never;
      }
      return {
        findOne: vi.fn().mockResolvedValue(null),
        find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        updateMany: vi.fn().mockResolvedValue({ modifiedCount: 0 }),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
        deleteMany: vi.fn().mockResolvedValue({ deletedCount: 0 }),
        countDocuments: vi.fn().mockResolvedValue(0),
        aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
      } as never;
    });
    app = await buildApp();
    unauthApp = await buildUnauthApp();
  });

  it("returns 401 when not authenticated", async () => {
    const res = await supertest(unauthApp).patch(`/api/findings/${FINDING_ID.toHexString()}`).send({ validation_status: "confirmed" });
    expect(res.status).toBe(401);
  });

  it("returns 404 for an invalid ObjectId format", async () => {
    const res = await supertest(app).patch("/api/findings/not-valid").send({ validation_status: "confirmed" });
    expect(res.status).toBe(404);
  });

  it("returns 200 when updating validation_status to confirmed", async () => {
    const res = await supertest(app).patch(`/api/findings/${FINDING_ID.toHexString()}`).send({ validation_status: "confirmed" });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("id");
  });

  it("returns 200 when updating notes", async () => {
    const res = await supertest(app).patch(`/api/findings/${FINDING_ID.toHexString()}`).send({ notes: "Verified by manual testing" });
    expect(res.status).toBe(200);
  });

  it("returns 200 when marking as false_positive with fp_reason", async () => {
    const res = await supertest(app).patch(`/api/findings/${FINDING_ID.toHexString()}`).send({
      validation_status: "false_positive",
      fp_reason: "WAF handles this attack vector",
    });
    expect(res.status).toBe(200);
  });

  it("returns 404 when finding is not found", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "findings") {
        return {
          findOne: vi.fn().mockResolvedValue(null),
          updateOne: vi.fn().mockResolvedValue({ modifiedCount: 0 }),
        } as never;
      }
      return { findOne: vi.fn().mockResolvedValue(null), updateOne: vi.fn().mockResolvedValue({ modifiedCount: 0 }) } as never;
    });
    const noFindingApp = await buildApp();
    const res = await supertest(noFindingApp).patch(`/api/findings/${new ObjectId().toHexString()}`).send({ validation_status: "confirmed" });
    expect(res.status).toBe(404);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/findings/bulk (POST version)", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "findings") {
        return {
          findOne: vi.fn().mockResolvedValue(mockFinding),
          find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ skip: vi.fn().mockReturnValue({ limit: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([mockFinding]) }) }) }) }),
          updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
          updateMany: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
          deleteMany: vi.fn().mockResolvedValue({ deletedCount: 1 }),
          countDocuments: vi.fn().mockResolvedValue(1),
        } as never;
      }
      return {
        findOne: vi.fn().mockResolvedValue(null),
        find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        updateMany: vi.fn().mockResolvedValue({ modifiedCount: 0 }),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
        deleteMany: vi.fn().mockResolvedValue({ deletedCount: 0 }),
        countDocuments: vi.fn().mockResolvedValue(0),
        aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
      } as never;
    });
    app = await buildApp();
  });

  it("returns 400 when ids array is empty", async () => {
    const res = await supertest(app).post("/api/findings/bulk").send({ ids: [], action: "mark_fp" });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("returns 400 when ids field is missing", async () => {
    const res = await supertest(app).post("/api/findings/bulk").send({ action: "mark_fp" });
    expect(res.status).toBe(400);
  });

  it("returns 400 when action is missing", async () => {
    const res = await supertest(app).post("/api/findings/bulk").send({ ids: [FINDING_ID.toHexString()] });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("returns 400 when all provided IDs are invalid ObjectIds", async () => {
    const res = await supertest(app).post("/api/findings/bulk").send({
      ids: ["not-valid", "also-not-valid"],
      action: "mark_fp",
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/valid finding IDs/i);
  });

  it("returns 200 and marks findings as false_positive", async () => {
    const res = await supertest(app).post("/api/findings/bulk").send({
      ids: [FINDING_ID.toHexString()],
      action: "mark_fp",
    });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("ok", true);
    expect(res.body.action).toBe("mark_fp");
  });

  it("returns 200 and marks findings as real", async () => {
    const res = await supertest(app).post("/api/findings/bulk").send({
      ids: [FINDING_ID.toHexString()],
      action: "mark_real",
    });
    expect(res.status).toBe(200);
    expect(res.body.action).toBe("mark_real");
  });

  it("returns 200 for bulk delete action", async () => {
    const res = await supertest(app).post("/api/findings/bulk").send({
      ids: [FINDING_ID.toHexString()],
      action: "delete",
    });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("ok", true);
  });

  it("returns 400 when more than 200 IDs are provided", async () => {
    const ids = Array.from({ length: 201 }, () => new ObjectId().toHexString());
    const res = await supertest(app).post("/api/findings/bulk").send({ ids, action: "mark_fp" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/200/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("PATCH /api/findings/bulk (PATCH version)", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "findings") {
        return {
          findOne: vi.fn().mockResolvedValue(mockFinding),
          updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
          updateMany: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
          deleteMany: vi.fn().mockResolvedValue({ deletedCount: 1 }),
          countDocuments: vi.fn().mockResolvedValue(1),
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
        aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
      } as never;
    });
    app = await buildApp();
  });

  it("returns 400 when ids array is empty", async () => {
    const res = await supertest(app).patch("/api/findings/bulk").send({ ids: [], action: "status", status: "confirmed" });
    expect(res.status).toBe(400);
  });

  it("returns 200 for bulk status update", async () => {
    const res = await supertest(app).patch("/api/findings/bulk").send({
      ids: [FINDING_ID.toHexString()],
      action: "status",
      status: "confirmed",
    });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("ok", true);
    expect(res.body).toHaveProperty("affected");
  });

  it("returns 200 for bulk assign action", async () => {
    const res = await supertest(app).patch("/api/findings/bulk").send({
      ids: [FINDING_ID.toHexString()],
      action: "assign",
      assignee_id: new ObjectId().toHexString(),
    });
    expect(res.status).toBe(200);
  });

  it("returns 200 for bulk accept_risk action", async () => {
    const res = await supertest(app).patch("/api/findings/bulk").send({
      ids: [FINDING_ID.toHexString()],
      action: "accept_risk",
      risk_reason: "Business accepted this risk",
    });
    expect(res.status).toBe(200);
  });

  it("returns 400 for unknown action", async () => {
    const res = await supertest(app).patch("/api/findings/bulk").send({
      ids: [FINDING_ID.toHexString()],
      action: "unknown_action",
    });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/findings/:id/evidence", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "findings") {
        return {
          findOne: vi.fn().mockResolvedValue(mockFinding),
          updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        } as never;
      }
      if (name === "evidence_files") {
        return {
          findOne: vi.fn().mockResolvedValue(null),
          find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }),
          insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        } as never;
      }
      return {
        findOne: vi.fn().mockResolvedValue(null),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
        countDocuments: vi.fn().mockResolvedValue(0),
        aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
      } as never;
    });
    app = await buildApp();
  });

  it("returns 201 when uploading a valid PNG evidence file", async () => {
    const base64Png = Buffer.from("fake-image-data").toString("base64");
    const res = await supertest(app)
      .post(`/api/findings/${FINDING_ID.toHexString()}/evidence`)
      .send({
        filename: "screenshot.png",
        content_type: "image/png",
        data: base64Png,
        description: "Proof of concept screenshot",
      });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty("id");
    expect(res.body).toHaveProperty("filename", "screenshot.png");
    expect(res.body).toHaveProperty("size_bytes");
  });

  it("returns 400 when filename is missing", async () => {
    const res = await supertest(app)
      .post(`/api/findings/${FINDING_ID.toHexString()}/evidence`)
      .send({
        content_type: "image/png",
        data: Buffer.from("data").toString("base64"),
      });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("returns 400 when data (base64) is missing", async () => {
    const res = await supertest(app)
      .post(`/api/findings/${FINDING_ID.toHexString()}/evidence`)
      .send({ filename: "file.png", content_type: "image/png" });
    expect(res.status).toBe(400);
  });

  it("returns 400 for a disallowed content type (e.g. application/exe)", async () => {
    const res = await supertest(app)
      .post(`/api/findings/${FINDING_ID.toHexString()}/evidence`)
      .send({
        filename: "malware.exe",
        content_type: "application/x-msdownload",
        data: Buffer.from("MZ").toString("base64"),
      });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/not allowed/i);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("GET /api/findings/:id/cve-details", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "findings") {
        return {
          findOne: vi.fn().mockResolvedValue(mockFinding),
          find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ skip: vi.fn().mockReturnValue({ limit: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([mockFinding]) }) }) }) }),
          updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
          countDocuments: vi.fn().mockResolvedValue(1),
        } as never;
      }
      return {
        findOne: vi.fn().mockResolvedValue(null),
        find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
        countDocuments: vi.fn().mockResolvedValue(0),
        aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
      } as never;
    });
    app = await buildApp();
  });

  it("returns 404 for invalid ObjectId", async () => {
    const res = await supertest(app).get("/api/findings/not-an-id/cve-details");
    expect(res.status).toBe(404);
  });

  it("returns 404 when finding does not exist", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "findings") return { findOne: vi.fn().mockResolvedValue(null) } as never;
      return { findOne: vi.fn().mockResolvedValue(null) } as never;
    });
    const noFindingApp = await buildApp();
    const res = await supertest(noFindingApp).get(`/api/findings/${new ObjectId().toHexString()}/cve-details`);
    expect(res.status).toBe(404);
  });

  it("returns CVE enrichment data when finding exists", async () => {
    const res = await supertest(app).get(`/api/findings/${FINDING_ID.toHexString()}/cve-details`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("finding_id");
    expect(res.body).toHaveProperty("cve_id");
    expect(res.body).toHaveProperty("epss_score");
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("GET /api/findings/enrich-all", () => {
  let adminApp: Awaited<ReturnType<typeof buildApp>>;
  let analystApp: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();

    // Set up findings mock with project() chaining for admin enrich-all
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "findings") {
        const chainable = {
          findOne: vi.fn().mockResolvedValue(mockFinding),
          find: vi.fn().mockReturnValue({
            sort: vi.fn().mockReturnValue({
              skip: vi.fn().mockReturnValue({
                limit: vi.fn().mockReturnValue({
                  toArray: vi.fn().mockResolvedValue([mockFinding]),
                }),
              }),
            }),
            project: vi.fn().mockReturnValue({
              limit: vi.fn().mockReturnValue({
                toArray: vi.fn().mockResolvedValue([]),
              }),
            }),
          }),
          insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
          updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
          updateMany: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
          deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
          deleteMany: vi.fn().mockResolvedValue({ deletedCount: 1 }),
          countDocuments: vi.fn().mockResolvedValue(1),
          aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
        };
        return chainable as never;
      }
      return {
        findOne: vi.fn().mockResolvedValue(null),
        find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        updateMany: vi.fn().mockResolvedValue({ modifiedCount: 0 }),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 0 }),
        deleteMany: vi.fn().mockResolvedValue({ deletedCount: 0 }),
        countDocuments: vi.fn().mockResolvedValue(0),
        aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
      } as never;
    });

    adminApp = await buildApp("admin");
    analystApp = await buildApp("analyst");
  });

  it("returns 403 when called by a non-admin user", async () => {
    const res = await supertest(analystApp).get("/api/findings/enrich-all");
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/admin/i);
  });

  it("returns 200 and queued count when called by admin", async () => {
    const res = await supertest(adminApp).get("/api/findings/enrich-all");
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("ok", true);
    expect(res.body).toHaveProperty("queued");
    expect(typeof res.body.queued).toBe("number");
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("GET /api/findings/:id/history", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "findings") return { findOne: vi.fn().mockResolvedValue(mockFinding), find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ skip: vi.fn().mockReturnValue({ limit: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([mockFinding]) }) }) }) }), updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }), countDocuments: vi.fn().mockResolvedValue(1) } as never;
      return { findOne: vi.fn().mockResolvedValue(null), insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }), updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }), deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }), countDocuments: vi.fn().mockResolvedValue(0), aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) } as never;
    });
    app = await buildApp();
  });

  it("returns 404 for invalid ObjectId", async () => {
    const res = await supertest(app).get("/api/findings/bad-id/history");
    expect(res.status).toBe(404);
  });

  it("returns history array for a valid finding", async () => {
    const res = await supertest(app).get(`/api/findings/${FINDING_ID.toHexString()}/history`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("history");
    expect(Array.isArray(res.body.history)).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/findings/:id/accept-risk", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "findings") return { findOne: vi.fn().mockResolvedValue(mockFinding), updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }), countDocuments: vi.fn().mockResolvedValue(1) } as never;
      return { findOne: vi.fn().mockResolvedValue(null), insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }), updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }), deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }), countDocuments: vi.fn().mockResolvedValue(0), aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) } as never;
    });
    app = await buildApp();
  });

  it("returns 400 when justification is missing", async () => {
    const res = await supertest(app).post(`/api/findings/${FINDING_ID.toHexString()}/accept-risk`).send({});
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/justification/i);
  });

  it("returns 200 when justification is provided", async () => {
    const res = await supertest(app)
      .post(`/api/findings/${FINDING_ID.toHexString()}/accept-risk`)
      .send({ justification: "Compensating controls in place", owner_name: "CISO" });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("ok", true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("GET /api/fp-suppressions", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "fp_suppressions") return { find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }), findOne: vi.fn().mockResolvedValue(null), updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }), deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }) } as never;
      if (name === "findings") return { findOne: vi.fn().mockResolvedValue(mockFinding), find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ skip: vi.fn().mockReturnValue({ limit: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([mockFinding]) }) }) }) }), updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }), countDocuments: vi.fn().mockResolvedValue(1) } as never;
      return { findOne: vi.fn().mockResolvedValue(null), insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }), updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }), deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }), countDocuments: vi.fn().mockResolvedValue(0), aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) } as never;
    });
    app = await buildApp();
  });

  it("returns list of FP suppressions", async () => {
    const res = await supertest(app).get("/api/fp-suppressions");
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("GET /api/findings/saved-filters", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "saved_filters") return { find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }), insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }), deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }) } as never;
      if (name === "findings") return { findOne: vi.fn().mockResolvedValue(mockFinding), find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ skip: vi.fn().mockReturnValue({ limit: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([mockFinding]) }) }) }) }), updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }), countDocuments: vi.fn().mockResolvedValue(1) } as never;
      return { findOne: vi.fn().mockResolvedValue(null), insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }), updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }), deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }), countDocuments: vi.fn().mockResolvedValue(0), aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) } as never;
    });
    app = await buildApp();
  });

  it("returns saved filter list", async () => {
    const res = await supertest(app).get("/api/findings/saved-filters");
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });
});

describe("POST /api/findings/saved-filters", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "saved_filters") return { find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }), insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }), deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }) } as never;
      if (name === "findings") return { findOne: vi.fn().mockResolvedValue(mockFinding), find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ skip: vi.fn().mockReturnValue({ limit: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([mockFinding]) }) }) }) }), updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }), countDocuments: vi.fn().mockResolvedValue(1) } as never;
      return { findOne: vi.fn().mockResolvedValue(null), insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }), updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }), deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }), countDocuments: vi.fn().mockResolvedValue(0), aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) } as never;
    });
    app = await buildApp();
  });

  it("returns 400 when name or filters is missing", async () => {
    const res = await supertest(app).post("/api/findings/saved-filters").send({ name: "My Filter" });
    expect(res.status).toBe(400);
  });

  it("returns 201 when filter is created", async () => {
    const res = await supertest(app).post("/api/findings/saved-filters").send({
      name: "Critical Only",
      filters: { severity: "critical" },
    });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty("name", "Critical Only");
  });
});
