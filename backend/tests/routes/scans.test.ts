/**
 * scans.test.ts — Integration tests for /scan-jobs/* endpoints
 *
 * Mocks:
 *  - ../../src/lib/db
 *  - ../../src/lib/redis
 *  - ../../src/lib/audit
 *  - ../../src/lib/ssrf-guard  → allow/block based on URL
 *  - ../../src/services/queue/manager → enqueueScan returns { ok: true }
 *  - ../../src/lib/pii-redact  → identity
 *  - ../../src/lib/compliance-map → []
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import express from "express";
import session from "express-session";
import supertest from "supertest";
import { ObjectId } from "mongodb";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const USER_ID = new ObjectId().toHexString();
const SCAN_ID = new ObjectId();

const mockScanJob = {
  _id: SCAN_ID,
  target_url: "https://example.com",
  scan_profile: "standard",
  user_id: USER_ID,
  status: "running",
  progress: 50,
  created_at: new Date(),
  started_at: new Date(),
  completed_at: null,
  findings_count: 3,
  critical_count: 1,
  high_count: 2,
  medium_count: 0,
  low_count: 0,
  info_count: 0,
  risk_score: 75,
  ai_summary: null,
  validation_enabled: true,
  fuzzing_enabled: false,
  bug_bounty_mode: false,
  authorization_acknowledged: true,
  scanner_engines: ["tls_check", "header_scan"],
  error_message: null,
  scope_hosts: [],
  diff_stats: null,
};

const mockFinding = {
  _id: new ObjectId(),
  title: "XSS Vulnerability",
  category: "XSS",
  severity: "high",
  validation_status: "needs_review",
  confidence: 0.9,
  endpoint: "/search",
  description: "Reflected XSS in search param",
  scanner_name: "xss_scanner",
  created_at: new Date(),
  target_url: "https://example.com",
  scan_job_id: SCAN_ID,
  user_id: USER_ID,
};

// ── Mocks ─────────────────────────────────────────────────────────────────────

vi.mock("../../src/lib/db", () => ({
  col: vi.fn((name: string) => {
    if (name === "scan_jobs") {
      return {
        findOne: vi.fn().mockResolvedValue(mockScanJob),
        findOneAndUpdate: vi.fn().mockResolvedValue(mockScanJob),
        find: vi.fn().mockReturnValue({
          sort: vi.fn().mockReturnValue({
            skip: vi.fn().mockReturnValue({
              limit: vi.fn().mockReturnValue({
                toArray: vi.fn().mockResolvedValue([mockScanJob]),
              }),
            }),
            limit: vi.fn().mockReturnValue({
              toArray: vi.fn().mockResolvedValue([mockScanJob]),
            }),
            toArray: vi.fn().mockResolvedValue([mockScanJob]),
          }),
        }),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
        countDocuments: vi.fn().mockResolvedValue(1),
        aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
      };
    }
    if (name === "findings") {
      return {
        findOne: vi.fn().mockResolvedValue(mockFinding),
        find: vi.fn().mockReturnValue({
          toArray: vi.fn().mockResolvedValue([mockFinding]),
          sort: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([mockFinding]) }),
        }),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 0 }),
        updateMany: vi.fn().mockResolvedValue({ modifiedCount: 0 }),
        countDocuments: vi.fn().mockResolvedValue(1),
      };
    }
    if (name === "activity_events") {
      return {
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
      };
    }
    if (name === "scan_templates") {
      return { findOne: vi.fn().mockResolvedValue(null) };
    }
    // Catch-all
    return {
      findOne: vi.fn().mockResolvedValue(null),
      find: vi.fn().mockReturnValue({
        sort: vi.fn().mockReturnValue({
          skip: vi.fn().mockReturnValue({ limit: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }),
          limit: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
          toArray: vi.fn().mockResolvedValue([]),
        }),
        limit: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
        toArray: vi.fn().mockResolvedValue([]),
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

vi.mock("../../src/lib/audit", () => ({
  auditFromReq: vi.fn().mockResolvedValue(undefined),
  logAudit: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../../src/lib/ssrf-guard", () => ({
  checkSsrf: vi.fn((url: string) => {
    const blocked = ["localhost", "127.", "192.168.", "10.", "169.254.169.254", "metadata.google"];
    const isBlocked = blocked.some((b) => url.includes(b));
    return isBlocked
      ? { allowed: false, reason: "Private or reserved IP address" }
      : { allowed: true };
  }),
}));

vi.mock("../../src/services/queue/manager", () => ({
  enqueueScan: vi.fn().mockResolvedValue({ ok: true }),
}));

vi.mock("../../src/lib/pii-redact", () => ({
  redactObject: vi.fn((obj: unknown) => obj),
  FINDING_SENSITIVE_FIELDS: [],
}));

vi.mock("../../src/lib/compliance-map", () => ({
  getComplianceTags: vi.fn().mockReturnValue([]),
}));

vi.mock("../../src/services/scanner/index", () => ({
  runScanPipeline: vi.fn().mockResolvedValue(undefined),
  scanEvents: { emit: vi.fn() },
  enqueueScan: vi.fn().mockResolvedValue({ ok: true }),
}));

vi.mock("../../src/middlewares/resource-rbac", () => ({
  engagementScopeFilter: vi.fn().mockReturnValue(null),
}));

vi.mock("../../src/services/dedup", () => ({
  clusterFindings: vi.fn().mockResolvedValue([]),
}));

vi.mock("../../src/services/vuln-intel", () => ({
  enrichFindingWithIntel: vi.fn().mockResolvedValue(undefined),
}));

// ── Build test app ─────────────────────────────────────────────────────────────

async function buildApp(role: "analyst" | "admin" = "analyst", sessionUserId = USER_ID) {
  const app = express();
  app.use(express.json());
  app.use(
    session({
      secret: "test-secret-at-least-32-chars-long!",
      resave: false,
      saveUninitialized: false,
    })
  );

  // Inject authenticated session
  app.use((req, _res, next) => {
    const sess = req.session as Record<string, unknown>;
    sess["userId"] = sessionUserId;
    sess["username"] = "test_user";
    sess["role"] = role;
    sess["created_at"] = Date.now();
    next();
  });

  const { default: scansRouter } = await import("../../src/routes/scans");
  const { default: findingsRouter } = await import("../../src/routes/findings");
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
  // No session injection
  const { default: scansRouter } = await import("../../src/routes/scans");
  app.use("/api", scansRouter);
  return app;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test suites
// ─────────────────────────────────────────────────────────────────────────────

describe("GET /api/scan-jobs", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;
  let unauthApp: Awaited<ReturnType<typeof buildUnauthApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    app = await buildApp();
    unauthApp = await buildUnauthApp();
  });

  it("returns 401 when not authenticated", async () => {
    const res = await supertest(unauthApp).get("/api/scan-jobs");
    expect(res.status).toBe(401);
  });

  it("returns paginated list of scan jobs", async () => {
    const res = await supertest(app).get("/api/scan-jobs");
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("items");
    expect(res.body).toHaveProperty("total");
    expect(res.body).toHaveProperty("page");
    expect(res.body).toHaveProperty("page_size");
    expect(Array.isArray(res.body.items)).toBe(true);
  });

  it("filters by status query param", async () => {
    const res = await supertest(app).get("/api/scan-jobs?status=running");
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("items");
  });

  it("accepts page and page_size query params", async () => {
    const res = await supertest(app).get("/api/scan-jobs?page=2&page_size=10");
    expect(res.status).toBe(200);
    expect(res.body.page).toBe(2);
    expect(res.body.page_size).toBe(10);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/scan-jobs", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    app = await buildApp();
  });

  it("returns 201 and created scan job for a valid public target URL", async () => {
    const res = await supertest(app).post("/api/scan-jobs").send({
      target_url: "https://example.com",
      scan_profile: "standard",
      authorization_acknowledged: true,
    });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty("id");
    expect(res.body).toHaveProperty("target_url");
    expect(res.body).toHaveProperty("status");
  });

  it("returns 400 when target_url is missing", async () => {
    const res = await supertest(app).post("/api/scan-jobs").send({
      scan_profile: "standard",
      authorization_acknowledged: true,
    });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("returns 400 when scan_profile is missing", async () => {
    const res = await supertest(app).post("/api/scan-jobs").send({
      target_url: "https://example.com",
      authorization_acknowledged: true,
    });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("returns 400 when authorization is not acknowledged", async () => {
    const res = await supertest(app).post("/api/scan-jobs").send({
      target_url: "https://example.com",
      scan_profile: "standard",
      authorization_acknowledged: false,
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/authorization/i);
  });

  it("returns 400 when targeting localhost (SSRF blocked)", async () => {
    const res = await supertest(app).post("/api/scan-jobs").send({
      target_url: "http://localhost:8080/admin",
      scan_profile: "standard",
      authorization_acknowledged: true,
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/not allowed/i);
  });

  it("returns 400 when targeting 127.0.0.1 (SSRF blocked)", async () => {
    const res = await supertest(app).post("/api/scan-jobs").send({
      target_url: "http://127.0.0.1:9200",
      scan_profile: "standard",
      authorization_acknowledged: true,
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/not allowed/i);
  });

  it("returns 400 when targeting AWS metadata endpoint (SSRF blocked)", async () => {
    const res = await supertest(app).post("/api/scan-jobs").send({
      target_url: "http://169.254.169.254/latest/meta-data/",
      scan_profile: "standard",
      authorization_acknowledged: true,
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/not allowed/i);
  });

  it("returns 400 when targeting private 192.168.x.x range (SSRF blocked)", async () => {
    const res = await supertest(app).post("/api/scan-jobs").send({
      target_url: "http://192.168.1.100",
      scan_profile: "standard",
      authorization_acknowledged: true,
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/not allowed/i);
  });

  it("returns 503 when the scan queue is full", async () => {
    const { enqueueScan } = await import("../../src/services/queue/manager");
    vi.mocked(enqueueScan).mockResolvedValueOnce({ ok: false, reason: "Queue is full" });
    const res = await supertest(app).post("/api/scan-jobs").send({
      target_url: "https://example.com",
      scan_profile: "standard",
      authorization_acknowledged: true,
    });
    expect(res.status).toBe(503);
    expect(res.body).toHaveProperty("error");
  });
});

// ─────────────────────────────────────────────────────────────────────────────

// Helper to restore the default col mock (used in beforeEach blocks that follow tests which override col)
async function restoreDefaultColMock() {
  const { col } = await import("../../src/lib/db");
  vi.mocked(col).mockImplementation((name: string) => {
    if (name === "scan_jobs") {
      return {
        findOne: vi.fn().mockResolvedValue(mockScanJob),
        findOneAndUpdate: vi.fn().mockResolvedValue(mockScanJob),
        find: vi.fn().mockReturnValue({
          sort: vi.fn().mockReturnValue({
            skip: vi.fn().mockReturnValue({ limit: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([mockScanJob]) }) }),
            limit: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([mockScanJob]) }),
            toArray: vi.fn().mockResolvedValue([mockScanJob]),
          }),
        }),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
        countDocuments: vi.fn().mockResolvedValue(1),
        aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
      } as never;
    }
    if (name === "findings") {
      return {
        findOne: vi.fn().mockResolvedValue(mockFinding),
        find: vi.fn().mockReturnValue({
          toArray: vi.fn().mockResolvedValue([mockFinding]),
          sort: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([mockFinding]) }),
        }),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 0 }),
        updateMany: vi.fn().mockResolvedValue({ modifiedCount: 0 }),
        countDocuments: vi.fn().mockResolvedValue(1),
      } as never;
    }
    return {
      findOne: vi.fn().mockResolvedValue(null),
      find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ skip: vi.fn().mockReturnValue({ limit: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }), limit: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }), toArray: vi.fn().mockResolvedValue([]) }), limit: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }), toArray: vi.fn().mockResolvedValue([]) }),
      insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
      updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
      updateMany: vi.fn().mockResolvedValue({ modifiedCount: 0 }),
      deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
      deleteMany: vi.fn().mockResolvedValue({ deletedCount: 0 }),
      countDocuments: vi.fn().mockResolvedValue(0),
      aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
    } as never;
  });
}

describe("GET /api/scan-jobs/:id", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    await restoreDefaultColMock();
    app = await buildApp();
  });

  it("returns 404 for an invalid ObjectId", async () => {
    const res = await supertest(app).get("/api/scan-jobs/not-an-id");
    expect(res.status).toBe(404);
  });

  it("returns 404 when scan job does not exist", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "scan_jobs") return { findOne: vi.fn().mockResolvedValue(null) } as never;
      return { findOne: vi.fn().mockResolvedValue(null) } as never;
    });
    const noScanApp = await buildApp();
    const res = await supertest(noScanApp).get(`/api/scan-jobs/${new ObjectId().toHexString()}`);
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/not found/i);
  });

  it("returns scan job data for a valid ID owned by the user", async () => {
    const res = await supertest(app).get(`/api/scan-jobs/${SCAN_ID.toHexString()}`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("id");
    expect(res.body).toHaveProperty("target_url");
    expect(res.body).toHaveProperty("status");
  });

  it("returns 403 when scan belongs to a different user (non-admin)", async () => {
    const DIFFERENT_USER = new ObjectId().toHexString();
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "scan_jobs") {
        return {
          findOne: vi.fn().mockResolvedValue({ ...mockScanJob, user_id: DIFFERENT_USER }),
        } as never;
      }
      return { findOne: vi.fn().mockResolvedValue(null) } as never;
    });
    const differentOwnerApp = await buildApp("analyst");
    const res = await supertest(differentOwnerApp).get(`/api/scan-jobs/${SCAN_ID.toHexString()}`);
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/forbidden/i);
  });

  it("admin can view any user's scan", async () => {
    const DIFFERENT_USER = new ObjectId().toHexString();
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "scan_jobs") {
        return {
          findOne: vi.fn().mockResolvedValue({ ...mockScanJob, user_id: DIFFERENT_USER }),
        } as never;
      }
      return { findOne: vi.fn().mockResolvedValue(null) } as never;
    });
    const adminApp = await buildApp("admin");
    const res = await supertest(adminApp).get(`/api/scan-jobs/${SCAN_ID.toHexString()}`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("id");
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("DELETE /api/scan-jobs/:id", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    await restoreDefaultColMock();
    app = await buildApp();
  });

  it("returns 404 for an invalid ObjectId", async () => {
    const res = await supertest(app).delete("/api/scan-jobs/not-an-id");
    expect(res.status).toBe(404);
  });

  it("returns 404 when scan does not exist", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "scan_jobs") return { findOne: vi.fn().mockResolvedValue(null), deleteOne: vi.fn() } as never;
      return { findOne: vi.fn().mockResolvedValue(null) } as never;
    });
    const noScanApp = await buildApp();
    const res = await supertest(noScanApp).delete(`/api/scan-jobs/${new ObjectId().toHexString()}`);
    expect(res.status).toBe(404);
  });

  it("returns 200/204 and cancels/deletes a running scan", async () => {
    const res = await supertest(app).delete(`/api/scan-jobs/${SCAN_ID.toHexString()}`);
    // Route returns 200 with { ok: true } for abort path, 204 for simple delete path
    expect([200, 204]).toContain(res.status);
  });

  it("returns 400 when scan is already completed (cannot abort)", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "scan_jobs") {
        return {
          findOne: vi.fn().mockResolvedValue({ ...mockScanJob, status: "completed" }),
          deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
          updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        } as never;
      }
      return {
        findOne: vi.fn().mockResolvedValue(null),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 0 }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 0 }),
      } as never;
    });
    const completedScanApp = await buildApp();
    const res = await supertest(completedScanApp).delete(`/api/scan-jobs/${SCAN_ID.toHexString()}`);
    // The abort route returns 400 for non-running/queued status
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/scan-jobs/:id/pause", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    await restoreDefaultColMock();
    app = await buildApp();
  });

  it("returns 404 for invalid ObjectId", async () => {
    const res = await supertest(app).post("/api/scan-jobs/bad-id/pause");
    expect(res.status).toBe(404);
  });

  it("returns 200 when pausing a scan", async () => {
    const res = await supertest(app).post(`/api/scan-jobs/${SCAN_ID.toHexString()}/pause`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("ok", true);
    expect(res.body).toHaveProperty("status", "paused");
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("PATCH /api/scan-jobs/:id/pause (PATCH variant)", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    await restoreDefaultColMock();
    app = await buildApp();
  });

  it("returns 200 and paused status", async () => {
    const res = await supertest(app).patch(`/api/scan-jobs/${SCAN_ID.toHexString()}/pause`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("ok", true);
    expect(res.body).toHaveProperty("status", "paused");
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/scan-jobs/:id/resume", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    await restoreDefaultColMock();
    app = await buildApp();
  });

  it("returns 404 for an invalid ObjectId", async () => {
    const res = await supertest(app).post("/api/scan-jobs/bad-id/resume");
    expect(res.status).toBe(404);
  });

  it("returns 200 when resuming a paused scan (POST)", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "scan_jobs") {
        return {
          findOne: vi.fn().mockResolvedValue({ ...mockScanJob, status: "paused" }),
          findOneAndUpdate: vi.fn().mockResolvedValue({ ...mockScanJob, status: "running" }),
          updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        } as never;
      }
      return {
        findOne: vi.fn().mockResolvedValue(null),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
      } as never;
    });
    const pausedApp = await buildApp();
    const res = await supertest(pausedApp).post(`/api/scan-jobs/${SCAN_ID.toHexString()}/resume`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("ok", true);
  });

  it("returns 404 when scan is not found or not paused (POST variant)", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "scan_jobs") {
        return {
          findOneAndUpdate: vi.fn().mockResolvedValue(null), // not paused
          findOne: vi.fn().mockResolvedValue({ ...mockScanJob, status: "running" }),
          updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        } as never;
      }
      return { findOne: vi.fn().mockResolvedValue(null) } as never;
    });
    const runningApp = await buildApp();
    const res = await supertest(runningApp).post(`/api/scan-jobs/${SCAN_ID.toHexString()}/resume`);
    expect(res.status).toBe(404);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("PATCH /api/scan-jobs/:id/resume (PATCH variant)", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    await restoreDefaultColMock();
    app = await buildApp();
  });

  it("returns 200 and running status", async () => {
    const res = await supertest(app).patch(`/api/scan-jobs/${SCAN_ID.toHexString()}/resume`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("ok", true);
    expect(res.body).toHaveProperty("status", "running");
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("GET /api/scan-jobs/:id/findings", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    await restoreDefaultColMock();
    app = await buildApp();
  });

  it("returns 404 for invalid ObjectId", async () => {
    const res = await supertest(app).get("/api/scan-jobs/bad-id/findings");
    expect(res.status).toBe(404);
  });

  it("returns array of findings for a valid scan job", async () => {
    const res = await supertest(app).get(`/api/scan-jobs/${SCAN_ID.toHexString()}/findings`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  it("filters by severity query param", async () => {
    const res = await supertest(app).get(`/api/scan-jobs/${SCAN_ID.toHexString()}/findings?severity=high`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  it("filters by validation_status query param", async () => {
    const res = await supertest(app).get(`/api/scan-jobs/${SCAN_ID.toHexString()}/findings?validation_status=confirmed`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/scan-jobs/:id/cancel", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    await restoreDefaultColMock();
    // Mock scanEvents
    vi.mock("../../src/services/scanner/index", () => ({
      runScanPipeline: vi.fn().mockResolvedValue(undefined),
      scanEvents: { emit: vi.fn() },
    }));
    app = await buildApp();
  });

  it("returns 404 for invalid ObjectId", async () => {
    const res = await supertest(app).post("/api/scan-jobs/bad-id/cancel");
    expect(res.status).toBe(404);
  });

  it("returns 404 when scan job does not exist", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "scan_jobs") return { findOne: vi.fn().mockResolvedValue(null) } as never;
      return { findOne: vi.fn().mockResolvedValue(null) } as never;
    });
    const noScanApp = await buildApp();
    const res = await supertest(noScanApp).post(`/api/scan-jobs/${new ObjectId().toHexString()}/cancel`);
    expect(res.status).toBe(404);
  });

  it("returns 400 when scan is already completed (cannot cancel)", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "scan_jobs") {
        return {
          findOne: vi.fn().mockResolvedValue({ ...mockScanJob, status: "completed" }),
          updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        } as never;
      }
      return { findOne: vi.fn().mockResolvedValue(null) } as never;
    });
    const completedApp = await buildApp();
    const res = await supertest(completedApp).post(`/api/scan-jobs/${SCAN_ID.toHexString()}/cancel`);
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/cancelled|cancel/i);
  });

  it("returns 200 when cancelling a running scan", async () => {
    const res = await supertest(app).post(`/api/scan-jobs/${SCAN_ID.toHexString()}/cancel`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("ok", true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/scan-jobs/bulk", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    await restoreDefaultColMock();
    app = await buildApp();
  });

  it("returns 400 when target_urls is empty", async () => {
    const res = await supertest(app).post("/api/scan-jobs/bulk").send({ target_urls: [] });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("returns 400 when target_urls is missing", async () => {
    const res = await supertest(app).post("/api/scan-jobs/bulk").send({});
    expect(res.status).toBe(400);
  });

  it("returns 400 when more than 20 URLs provided", async () => {
    const urls = Array.from({ length: 21 }, (_, i) => `https://target${i}.example.com`);
    const res = await supertest(app).post("/api/scan-jobs/bulk").send({ target_urls: urls });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/20/);
  });

  it("returns 201 for valid bulk scan request", async () => {
    const res = await supertest(app).post("/api/scan-jobs/bulk").send({
      target_urls: ["https://example.com", "https://test.example.com"],
      profile: "standard",
    });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty("ok", true);
    expect(res.body).toHaveProperty("scans");
    expect(Array.isArray(res.body.scans)).toBe(true);
  });

  it("returns 400 when no valid URLs are provided", async () => {
    const res = await supertest(app).post("/api/scan-jobs/bulk").send({
      target_urls: ["not-a-url", "also-not-a-url"],
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/valid URLs/i);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("PATCH /api/scan-jobs/:id/priority", () => {
  let adminApp: Awaited<ReturnType<typeof buildApp>>;
  let analystApp: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    await restoreDefaultColMock();
    adminApp = await buildApp("admin");
    analystApp = await buildApp("analyst");
  });

  it("returns 403 when called by non-admin", async () => {
    const res = await supertest(analystApp).patch(`/api/scan-jobs/${SCAN_ID.toHexString()}/priority`).send({ priority: 8 });
    expect(res.status).toBe(403);
  });

  it("returns 400 when priority is out of range", async () => {
    const res = await supertest(adminApp).patch(`/api/scan-jobs/${SCAN_ID.toHexString()}/priority`).send({ priority: 11 });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/1-10/);
  });

  it("returns 200 for valid priority update by admin", async () => {
    const res = await supertest(adminApp).patch(`/api/scan-jobs/${SCAN_ID.toHexString()}/priority`).send({ priority: 9 });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("ok", true);
  });
});
