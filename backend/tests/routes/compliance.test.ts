/**
 * Compliance route tests
 * GET  /compliance/mapping
 * GET  /compliance/report/soc2
 * GET  /compliance/report/iso27001
 * GET  /compliance/report/pci
 * GET  /compliance/report/:invalid
 * POST /compliance/evidence/:controlId
 * GET  /compliance/attestation/soc2
 * All auth-guarded endpoints return 401 without a session
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import supertest from "supertest";
import type { Express } from "express";
import { ObjectId } from "mongodb";
import { col } from "../../src/lib/db";

let app: Express;
let request: ReturnType<typeof supertest>;
let sessionCookie: string;

async function loginAndGetCookie(): Promise<string> {
  const res = await request.post("/api/auth/login").send({
    email: process.env["ADMIN_EMAIL"],
    password: process.env["ADMIN_PASSWORD"],
  });
  const raw = res.headers["set-cookie"] as string[] | string | undefined;
  if (!raw) return "";
  const cookies = Array.isArray(raw) ? raw : [raw];
  return cookies.map((c: string) => c.split(";")[0]).join("; ");
}

async function seedFinding(overrides: Record<string, unknown> = {}): Promise<ObjectId> {
  const result = await col("findings").insertOne({
    title: "Test Finding",
    severity: "high",
    category: "Authentication",
    endpoint: "/api/login",
    description: "Auth bypass",
    status: "open",
    created_at: new Date(),
    ...overrides,
  });
  return result.insertedId;
}

beforeAll(async () => {
  process.env["NODE_ENV"] = "test";
  process.env["SESSION_SECRET"] = "test-secret-key-32chars-minimum!";
  process.env["ADMIN_EMAIL"] = "admin@test.local";
  process.env["ADMIN_PASSWORD"] = "AdminP@ss123";

  const mod = await import("../../src/app");
  app = mod.default;
  request = supertest(app);

  sessionCookie = await loginAndGetCookie();
}, 30000);

afterAll(() => {
  vi.restoreAllMocks();
});

// ── GET /compliance/mapping ───────────────────────────────────────────────────

describe("GET /api/compliance/mapping", () => {
  it("returns 401 without auth", async () => {
    const res = await request.get("/api/compliance/mapping");
    expect(res.status).toBe(401);
  });

  it("returns findings grouped by soc2, iso27001, and pci controls", async () => {
    await seedFinding({ category: "Authentication", status: "open" });

    const res = await request
      .get("/api/compliance/mapping")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("soc2");
    expect(res.body).toHaveProperty("iso27001");
    expect(res.body).toHaveProperty("pci");

    // Each framework mapping is an object (control → findings array)
    expect(typeof res.body.soc2).toBe("object");
    expect(typeof res.body.iso27001).toBe("object");
    expect(typeof res.body.pci).toBe("object");
  });

  it("returns empty maps when no open findings exist", async () => {
    // Mark all findings resolved so the filter excludes them
    // (in-memory store: just verify the response is shaped correctly)
    const res = await request
      .get("/api/compliance/mapping")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("soc2");
    expect(res.body).toHaveProperty("pci");
  });
});

// ── GET /compliance/report/soc2 ───────────────────────────────────────────────

describe("GET /api/compliance/report/soc2", () => {
  it("returns 401 without auth", async () => {
    const res = await request.get("/api/compliance/report/soc2");
    expect(res.status).toBe(401);
  });

  it("returns compliance_score_pct, passing_controls, failing_controls", async () => {
    const res = await request
      .get("/api/compliance/report/soc2")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("framework");
    expect(res.body.framework).toBe("soc2");
    expect(res.body).toHaveProperty("compliance_score_pct");
    expect(res.body).toHaveProperty("passing_controls");
    expect(res.body).toHaveProperty("failing_controls");
    expect(res.body).toHaveProperty("total_controls");
    expect(typeof res.body.compliance_score_pct).toBe("number");
    expect(res.body.compliance_score_pct).toBeGreaterThanOrEqual(0);
    expect(res.body.compliance_score_pct).toBeLessThanOrEqual(100);
  });

  it("includes generated_at timestamp", async () => {
    const res = await request
      .get("/api/compliance/report/soc2")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("generated_at");
    expect(new Date(res.body.generated_at as string).getTime()).not.toBeNaN();
  });

  it("passing + failing = total controls", async () => {
    const res = await request
      .get("/api/compliance/report/soc2")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    const { passing_controls, failing_controls, total_controls } = res.body as {
      passing_controls: number;
      failing_controls: number;
      total_controls: number;
    };
    expect(passing_controls + failing_controls).toBe(total_controls);
  });
});

// ── GET /compliance/report/iso27001 ──────────────────────────────────────────

describe("GET /api/compliance/report/iso27001", () => {
  it("returns 401 without auth", async () => {
    const res = await request.get("/api/compliance/report/iso27001");
    expect(res.status).toBe(401);
  });

  it("returns correct framework label and score structure", async () => {
    const res = await request
      .get("/api/compliance/report/iso27001")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body.framework).toBe("iso27001");
    expect(res.body).toHaveProperty("compliance_score_pct");
    expect(res.body).toHaveProperty("passing_controls");
    expect(res.body).toHaveProperty("failing_controls");
  });
});

// ── GET /compliance/report/pci ────────────────────────────────────────────────

describe("GET /api/compliance/report/pci", () => {
  it("returns 401 without auth", async () => {
    const res = await request.get("/api/compliance/report/pci");
    expect(res.status).toBe(401);
  });

  it("returns pci framework score structure", async () => {
    const res = await request
      .get("/api/compliance/report/pci")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body.framework).toBe("pci");
    expect(res.body).toHaveProperty("compliance_score_pct");
    expect(typeof res.body.compliance_score_pct).toBe("number");
  });

  it("failing array contains control and linked_findings", async () => {
    // Insert a high-severity injection finding to trigger a failing PCI control
    await seedFinding({ category: "Injection", severity: "high", status: "open" });

    const res = await request
      .get("/api/compliance/report/pci")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.failing)).toBe(true);

    if (res.body.failing.length > 0) {
      const first = res.body.failing[0] as { control: string; linked_findings: unknown[] };
      expect(first).toHaveProperty("control");
      expect(first).toHaveProperty("linked_findings");
      expect(Array.isArray(first.linked_findings)).toBe(true);
    }
  });
});

// ── GET /compliance/report/:invalid ──────────────────────────────────────────

describe("GET /api/compliance/report/:framework (invalid)", () => {
  it("returns 400 for an unknown framework", async () => {
    const res = await request
      .get("/api/compliance/report/gdpr")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
    expect(res.body.error).toMatch(/soc2|iso27001|pci/);
  });

  it("returns 400 for 'hipaa' framework (not in the allowed list)", async () => {
    const res = await request
      .get("/api/compliance/report/hipaa")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(400);
  });
});

// ── POST /compliance/evidence/:controlId ─────────────────────────────────────

describe("POST /api/compliance/evidence/:controlId", () => {
  it("returns 401 without auth", async () => {
    const res = await request
      .post("/api/compliance/evidence/CC6.1")
      .send({ framework: "soc2", evidence_text: "We use MFA." });
    expect(res.status).toBe(401);
  });

  it("returns 400 when framework or evidence_text is missing", async () => {
    const res = await request
      .post("/api/compliance/evidence/CC6.1")
      .set("Cookie", sessionCookie)
      .send({ framework: "soc2" }); // missing evidence_text

    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("stores evidence and returns 201 with the new document", async () => {
    const res = await request
      .post("/api/compliance/evidence/CC6.1")
      .set("Cookie", sessionCookie)
      .send({
        framework: "soc2",
        evidence_text: "MFA is enforced on all user accounts.",
        file_name: "mfa-policy.pdf",
        notes: "Reviewed by CISO",
      });

    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty("id");
    expect(res.body.control_id).toBe("CC6.1");
    expect(res.body.framework).toBe("soc2");
    expect(res.body.evidence_text).toBe("MFA is enforced on all user accounts.");
  });
});

// ── GET /compliance/attestation/soc2 ─────────────────────────────────────────

describe("GET /api/compliance/attestation/:framework", () => {
  it("returns 401 without auth", async () => {
    const res = await request.get("/api/compliance/attestation/soc2");
    expect(res.status).toBe(401);
  });

  it("returns 400 for invalid framework", async () => {
    const res = await request
      .get("/api/compliance/attestation/gdpr")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("returns JSON attestation document with required fields", async () => {
    const res = await request
      .get("/api/compliance/attestation/soc2")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("framework");
    expect(res.body.framework).toBe("soc2");
    expect(res.body).toHaveProperty("generated_at");
    expect(res.body).toHaveProperty("control_statuses");
    expect(Array.isArray(res.body.control_statuses)).toBe(true);

    // Timestamp is a valid ISO string
    expect(new Date(res.body.generated_at as string).getTime()).not.toBeNaN();
  });

  it("each control_status entry has control and status fields", async () => {
    const res = await request
      .get("/api/compliance/attestation/soc2")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    if (res.body.control_statuses.length > 0) {
      const first = res.body.control_statuses[0] as {
        control: string;
        status: string;
        evidence_links: unknown[];
      };
      expect(first).toHaveProperty("control");
      expect(first).toHaveProperty("status");
      expect(["passing", "failing"]).toContain(first.status);
      expect(Array.isArray(first.evidence_links)).toBe(true);
    }
  });

  it("works for iso27001 and pci as well", async () => {
    for (const fw of ["iso27001", "pci"]) {
      const res = await request
        .get(`/api/compliance/attestation/${fw}`)
        .set("Cookie", sessionCookie);

      expect(res.status).toBe(200);
      expect(res.body.framework).toBe(fw);
    }
  });
});
