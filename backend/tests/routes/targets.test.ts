/**
 * targets.test.ts — Integration tests for /targets/* endpoints
 *
 * Mocks:
 *  - ../../src/lib/db
 *  - ../../src/lib/audit
 *  - attack-surface-monitor service
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import express from "express";
import session from "express-session";
import supertest from "supertest";
import { ObjectId } from "mongodb";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const USER_ID = new ObjectId().toHexString();
const TARGET_ID = new ObjectId();

const mockTarget = {
  _id: TARGET_ID,
  url: "https://example.com",
  domain: "example.com",
  user_id: USER_ID,
  last_scanned: new Date("2025-01-10"),
  total_scans: 5,
  total_findings: 12,
  critical_findings: 2,
  high_findings: 4,
  risk_score: 70,
  status: "active",
  tags: ["production", "web"],
  tech_stack: ["Node.js", "MongoDB"],
  subdomains: ["api.example.com"],
  risk_history: [{ score: 65, date: "2024-12-01" }],
};

// ── Mocks ─────────────────────────────────────────────────────────────────────

vi.mock("../../src/lib/db", () => ({
  col: vi.fn((name: string) => {
    if (name === "targets") {
      return {
        findOne: vi.fn().mockResolvedValue(mockTarget),
        find: vi.fn().mockReturnValue({
          sort: vi.fn().mockReturnValue({
            toArray: vi.fn().mockResolvedValue([mockTarget]),
            skip: vi.fn().mockReturnValue({
              limit: vi.fn().mockReturnValue({
                toArray: vi.fn().mockResolvedValue([mockTarget]),
              }),
            }),
          }),
          toArray: vi.fn().mockResolvedValue([mockTarget]),
        }),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        deleteOne: vi.fn().mockResolvedValue({ deletedCount: 1 }),
        countDocuments: vi.fn().mockResolvedValue(1),
        aggregate: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
      };
    }
    if (name === "scan_jobs") {
      return {
        findOne: vi.fn().mockResolvedValue(null),
        find: vi.fn().mockReturnValue({
          sort: vi.fn().mockReturnValue({
            limit: vi.fn().mockReturnValue({
              toArray: vi.fn().mockResolvedValue([]),
            }),
          }),
        }),
      };
    }
    if (name === "findings") {
      return {
        find: vi.fn().mockReturnValue({
          sort: vi.fn().mockReturnValue({
            toArray: vi.fn().mockResolvedValue([]),
          }),
          toArray: vi.fn().mockResolvedValue([]),
        }),
      };
    }
    // Catch-all
    return {
      findOne: vi.fn().mockResolvedValue(null),
      find: vi.fn().mockReturnValue({
        sort: vi.fn().mockReturnValue({
          toArray: vi.fn().mockResolvedValue([]),
          limit: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }),
        }),
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

vi.mock("../../src/lib/audit", () => ({
  auditFromReq: vi.fn().mockResolvedValue(undefined),
  logAudit: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../../src/services/monitor/attack-surface-monitor", () => ({
  runAttackSurfaceMonitorForTarget: vi.fn().mockResolvedValue(undefined),
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

  // Inject authenticated session
  app.use((req, _res, next) => {
    const sess = req.session as Record<string, unknown>;
    sess["userId"] = USER_ID;
    sess["username"] = "test_user";
    sess["role"] = role;
    sess["created_at"] = Date.now();
    next();
  });

  const { default: targetsRouter } = await import("../../src/routes/targets");
  app.use("/api", targetsRouter);
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
  const { default: targetsRouter } = await import("../../src/routes/targets");
  app.use("/api", targetsRouter);
  return app;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test suites
// ─────────────────────────────────────────────────────────────────────────────

describe("GET /api/targets", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;
  let unauthApp: Awaited<ReturnType<typeof buildUnauthApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    app = await buildApp();
    unauthApp = await buildUnauthApp();
  });

  it("returns 401 when not authenticated", async () => {
    const res = await supertest(unauthApp).get("/api/targets");
    expect(res.status).toBe(401);
  });

  it("returns paginated targets list when authenticated", async () => {
    const res = await supertest(app).get("/api/targets");
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("items");
    expect(res.body).toHaveProperty("total");
    expect(res.body).toHaveProperty("page");
    expect(res.body).toHaveProperty("page_size");
    expect(Array.isArray(res.body.items)).toBe(true);
  });

  it("returns all_tags in response for filter sidebar", async () => {
    const res = await supertest(app).get("/api/targets");
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("all_tags");
    expect(Array.isArray(res.body.all_tags)).toBe(true);
  });

  it("handles search query param without error", async () => {
    const res = await supertest(app).get("/api/targets?search=example");
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("items");
  });

  it("handles tag filter query param", async () => {
    const res = await supertest(app).get("/api/targets?tag=production");
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("items");
  });

  it("accepts page and page_size query params", async () => {
    const res = await supertest(app).get("/api/targets?page=1&page_size=10");
    expect(res.status).toBe(200);
    expect(res.body.page).toBe(1);
    expect(res.body.page_size).toBe(10);
  });

  it("handles sort_by query param", async () => {
    const res = await supertest(app).get("/api/targets?sort_by=risk_score&sort_dir=desc");
    expect(res.status).toBe(200);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("GET /api/targets/:id", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;
  let unauthApp: Awaited<ReturnType<typeof buildUnauthApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    app = await buildApp();
    unauthApp = await buildUnauthApp();
  });

  it("returns 401 when not authenticated", async () => {
    const res = await supertest(unauthApp).get(`/api/targets/${TARGET_ID.toHexString()}`);
    expect(res.status).toBe(401);
  });

  it("returns 404 for an invalid (non-ObjectId) id", async () => {
    const res = await supertest(app).get("/api/targets/not-an-id");
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty("error");
  });

  it("returns 404 when target does not exist", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "targets") return { findOne: vi.fn().mockResolvedValue(null) } as never;
      return { findOne: vi.fn().mockResolvedValue(null) } as never;
    });
    const noTargetApp = await buildApp();
    const res = await supertest(noTargetApp).get(`/api/targets/${new ObjectId().toHexString()}`);
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/not found/i);
  });

  it("returns target data for a valid ID", async () => {
    const res = await supertest(app).get(`/api/targets/${TARGET_ID.toHexString()}`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("id");
    expect(res.body).toHaveProperty("url");
    expect(res.body).toHaveProperty("domain");
    expect(res.body).toHaveProperty("status");
    expect(res.body).toHaveProperty("risk_score");
  });

  it("returned target includes tags and tech_stack arrays", async () => {
    const res = await supertest(app).get(`/api/targets/${TARGET_ID.toHexString()}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.tags)).toBe(true);
    expect(Array.isArray(res.body.tech_stack)).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/targets/bulk-import", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;
  let unauthApp: Awaited<ReturnType<typeof buildUnauthApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();

    // For import: targets.findOne returns null (no existing duplicate) by default
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "targets") {
        return {
          findOne: vi.fn().mockResolvedValue(null), // no duplicates
          find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }),
          insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
          updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
        } as never;
      }
      return {
        findOne: vi.fn().mockResolvedValue(null),
        insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
      } as never;
    });

    app = await buildApp();
    unauthApp = await buildUnauthApp();
  });

  it("returns 401 when not authenticated", async () => {
    const res = await supertest(unauthApp).post("/api/targets/bulk-import").send({
      urls: ["https://example.com"],
    });
    expect(res.status).toBe(401);
  });

  it("returns 400 when urls array is missing", async () => {
    const res = await supertest(app).post("/api/targets/bulk-import").send({});
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("returns 400 when urls array is empty", async () => {
    const res = await supertest(app).post("/api/targets/bulk-import").send({ urls: [] });
    expect(res.status).toBe(400);
  });

  it("imports valid URLs and returns import count", async () => {
    const res = await supertest(app).post("/api/targets/bulk-import").send({
      urls: ["https://example.com", "https://test.example.com"],
      tags: ["imported"],
    });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("imported");
    expect(res.body).toHaveProperty("skipped");
    expect(res.body).toHaveProperty("total");
    expect(typeof res.body.imported).toBe("number");
  });

  it("skips invalid URLs and reports them in skipped count", async () => {
    const res = await supertest(app).post("/api/targets/bulk-import").send({
      urls: ["not-a-url", "https://valid.example.com"],
      tags: [],
    });
    expect(res.status).toBe(200);
    expect(res.body.skipped).toBeGreaterThanOrEqual(1);
    expect(res.body.total).toBe(2);
  });

  it("skips duplicate domains and merges tags", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "targets") {
        return {
          findOne: vi.fn().mockResolvedValue(mockTarget), // always finds duplicate
          find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }),
          updateOne: vi.fn().mockResolvedValue({ modifiedCount: 1 }),
          insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }),
        } as never;
      }
      return { findOne: vi.fn().mockResolvedValue(null), insertOne: vi.fn().mockResolvedValue({ insertedId: new ObjectId() }) } as never;
    });
    const dupApp = await buildApp();
    const res = await supertest(dupApp).post("/api/targets/bulk-import").send({
      urls: ["https://example.com"],
      tags: ["new-tag"],
    });
    expect(res.status).toBe(200);
    expect(res.body.skipped).toBe(1);
    expect(res.body.imported).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("PATCH /api/targets/:id/tags", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;
  let unauthApp: Awaited<ReturnType<typeof buildUnauthApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    app = await buildApp();
    unauthApp = await buildUnauthApp();
  });

  it("returns 401 when not authenticated", async () => {
    const res = await supertest(unauthApp).patch(`/api/targets/${TARGET_ID.toHexString()}/tags`).send({ tags: ["web"] });
    expect(res.status).toBe(401);
  });

  it("returns 404 for an invalid ObjectId", async () => {
    const res = await supertest(app).patch("/api/targets/bad-id/tags").send({ tags: ["web"] });
    expect(res.status).toBe(404);
  });

  it("returns 400 when tags is not an array", async () => {
    const res = await supertest(app).patch(`/api/targets/${TARGET_ID.toHexString()}/tags`).send({ tags: "not-an-array" });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/array/i);
  });

  it("returns 200 with updated target when tags are valid", async () => {
    const res = await supertest(app).patch(`/api/targets/${TARGET_ID.toHexString()}/tags`).send({
      tags: ["production", "web", "critical"],
    });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("id");
    expect(res.body).toHaveProperty("tags");
  });

  it("allows setting tags to an empty array", async () => {
    const res = await supertest(app).patch(`/api/targets/${TARGET_ID.toHexString()}/tags`).send({ tags: [] });
    expect(res.status).toBe(200);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("GET /api/targets/:id/risk-trend", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    app = await buildApp();
  });

  it("returns 404 for invalid ObjectId", async () => {
    const res = await supertest(app).get("/api/targets/bad-id/risk-trend");
    expect(res.status).toBe(404);
  });

  it("returns 404 when target does not exist", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "targets") return { findOne: vi.fn().mockResolvedValue(null) } as never;
      return { findOne: vi.fn().mockResolvedValue(null), find: vi.fn().mockReturnValue({ sort: vi.fn().mockReturnValue({ limit: vi.fn().mockReturnValue({ toArray: vi.fn().mockResolvedValue([]) }) }) }) } as never;
    });
    const noTargetApp = await buildApp();
    const res = await supertest(noTargetApp).get(`/api/targets/${new ObjectId().toHexString()}/risk-trend`);
    expect(res.status).toBe(404);
  });

  it("returns an array of risk trend data points", async () => {
    const res = await supertest(app).get(`/api/targets/${TARGET_ID.toHexString()}/risk-trend`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("GET /api/targets/:id/recurring-findings", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    app = await buildApp();
  });

  it("returns 404 for invalid ObjectId", async () => {
    const res = await supertest(app).get("/api/targets/bad-id/recurring-findings");
    expect(res.status).toBe(404);
  });

  it("returns recurring findings list for a valid target", async () => {
    const res = await supertest(app).get(`/api/targets/${TARGET_ID.toHexString()}/recurring-findings`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("POST /api/targets/:id/monitor", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    app = await buildApp();
  });

  it("returns 404 for invalid ObjectId", async () => {
    const res = await supertest(app).post("/api/targets/bad-id/monitor");
    expect(res.status).toBe(404);
  });

  it("returns 404 when target does not exist", async () => {
    const { col } = await import("../../src/lib/db");
    vi.mocked(col).mockImplementation((name: string) => {
      if (name === "targets") return { findOne: vi.fn().mockResolvedValue(null) } as never;
      return { findOne: vi.fn().mockResolvedValue(null) } as never;
    });
    const noTargetApp = await buildApp();
    const res = await supertest(noTargetApp).post(`/api/targets/${new ObjectId().toHexString()}/monitor`);
    expect(res.status).toBe(404);
  });

  it("returns 200 and kicks off background monitor", async () => {
    const res = await supertest(app).post(`/api/targets/${TARGET_ID.toHexString()}/monitor`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("ok", true);
    expect(res.body.message).toMatch(/background/i);
  });
});

// ─────────────────────────────────────────────────────────────────────────────

describe("GET /api/attack-surface", () => {
  let app: Awaited<ReturnType<typeof buildApp>>;
  let unauthApp: Awaited<ReturnType<typeof buildUnauthApp>>;

  beforeEach(async () => {
    vi.clearAllMocks();
    app = await buildApp();
    unauthApp = await buildUnauthApp();
  });

  it("returns 401 when not authenticated", async () => {
    const res = await supertest(unauthApp).get("/api/attack-surface");
    expect(res.status).toBe(401);
  });

  it("returns attack surface summary with expected keys", async () => {
    const res = await supertest(app).get("/api/attack-surface");
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("summary");
    expect(res.body).toHaveProperty("category_data");
    expect(res.body).toHaveProperty("endpoint_inventory");
    expect(res.body).toHaveProperty("heatmap");
    expect(res.body).toHaveProperty("exposure_trend");
  });

  it("summary contains total_targets and total_findings", async () => {
    const res = await supertest(app).get("/api/attack-surface");
    expect(res.status).toBe(200);
    expect(res.body.summary).toHaveProperty("total_targets");
    expect(res.body.summary).toHaveProperty("total_findings");
    expect(res.body.summary).toHaveProperty("critical");
    expect(res.body.summary).toHaveProperty("high");
  });

  it("accepts tag filter query param", async () => {
    const res = await supertest(app).get("/api/attack-surface?tag=production");
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("summary");
  });
});
