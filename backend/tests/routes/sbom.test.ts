/**
 * SBOM route tests
 * GET /sbom/:scanId          — CycloneDX JSON
 * GET /sbom/:scanId/download — attachment download
 * GET /sbom/:scanId/spdx     — SPDX JSON
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

// Seed a scan job and optionally some findings; returns scanId string
async function seedScan(findings: Array<Record<string, unknown>> = []): Promise<string> {
  const scanResult = await col("scan_jobs").insertOne({
    status: "completed",
    target_url: "https://example.com",
    created_at: new Date(),
    completed_at: new Date(),
  });
  const scanId = scanResult.insertedId;

  for (const f of findings) {
    await col("findings").insertOne({
      scan_job_id: scanId,
      title: "Test Finding",
      severity: "high",
      category: "Injection",
      endpoint: "https://example.com/api/login",
      description: "SQL injection",
      cve_id: "CVE-2023-12345",
      cwe_id: "CWE-89",
      cvss_score: 9.1,
      ...f,
    });
  }

  return scanId.toString();
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

// ── GET /sbom/:scanId ─────────────────────────────────────────────────────────

describe("GET /api/sbom/:scanId", () => {
  it("returns 401 without auth", async () => {
    const scanId = await seedScan();
    const res = await request.get(`/api/sbom/${scanId}`);
    expect(res.status).toBe(401);
  });

  it("returns 404 for a valid ObjectId that does not match any scan", async () => {
    const res = await request
      .get(`/api/sbom/${new ObjectId()}`)
      .set("Cookie", sessionCookie);
    expect(res.status).toBe(404);
  });

  it("returns 404 for a non-ObjectId string", async () => {
    const res = await request
      .get("/api/sbom/not-a-valid-id")
      .set("Cookie", sessionCookie);
    // getScanFindings returns null for invalid ObjectId → 404
    expect(res.status).toBe(404);
  });

  it("returns CycloneDX JSON with bomFormat and specVersion", async () => {
    const scanId = await seedScan([
      { endpoint: "https://example.com/api", cve_id: "CVE-2023-00001" },
    ]);

    const res = await request
      .get(`/api/sbom/${scanId}`)
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("bomFormat");
    expect(res.body.bomFormat).toBe("CycloneDX");
    expect(res.body).toHaveProperty("specVersion");
    expect(res.body.specVersion).toBe("1.4");
  });

  it("includes components array", async () => {
    const scanId = await seedScan([
      { endpoint: "https://target.example.com/login" },
    ]);

    const res = await request
      .get(`/api/sbom/${scanId}`)
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.components)).toBe(true);
  });

  it("includes vulnerabilities array (for findings with cve_id)", async () => {
    const scanId = await seedScan([
      {
        endpoint: "https://vuln.example.com/exec",
        cve_id: "CVE-2024-99999",
        cvss_score: 9.8,
      },
    ]);

    const res = await request
      .get(`/api/sbom/${scanId}`)
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.vulnerabilities)).toBe(true);
    expect(res.body.vulnerabilities.length).toBeGreaterThan(0);

    const vuln = res.body.vulnerabilities[0] as Record<string, unknown>;
    expect(vuln).toHaveProperty("id");
    expect(vuln).toHaveProperty("ratings");
    expect(Array.isArray(vuln.ratings)).toBe(true);
  });

  it("includes metadata with tools array", async () => {
    const scanId = await seedScan();

    const res = await request
      .get(`/api/sbom/${scanId}`)
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("metadata");
    expect(res.body.metadata).toHaveProperty("tools");
  });
});

// ── GET /sbom/:scanId/download ────────────────────────────────────────────────

describe("GET /api/sbom/:scanId/download", () => {
  it("returns 401 without auth", async () => {
    const scanId = await seedScan();
    const res = await request.get(`/api/sbom/${scanId}/download`);
    expect(res.status).toBe(401);
  });

  it("returns 404 for unknown scan", async () => {
    const res = await request
      .get(`/api/sbom/${new ObjectId()}/download`)
      .set("Cookie", sessionCookie);
    expect(res.status).toBe(404);
  });

  it("sets Content-Disposition: attachment header", async () => {
    const scanId = await seedScan();

    const res = await request
      .get(`/api/sbom/${scanId}/download`)
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    const disposition = res.headers["content-disposition"] as string;
    expect(disposition).toBeDefined();
    expect(disposition.toLowerCase()).toContain("attachment");
  });

  it("sets Content-Type: application/json", async () => {
    const scanId = await seedScan();

    const res = await request
      .get(`/api/sbom/${scanId}/download`)
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/application\/json/);
  });

  it("filename in Content-Disposition includes the scanId", async () => {
    const scanId = await seedScan();

    const res = await request
      .get(`/api/sbom/${scanId}/download`)
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    const disposition = res.headers["content-disposition"] as string;
    expect(disposition).toContain(scanId);
  });

  it("body is valid CycloneDX", async () => {
    const scanId = await seedScan([{ endpoint: "https://dl.example.com/" }]);

    const res = await request
      .get(`/api/sbom/${scanId}/download`)
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body.bomFormat).toBe("CycloneDX");
    expect(res.body.specVersion).toBe("1.4");
  });
});

// ── GET /sbom/:scanId/spdx ────────────────────────────────────────────────────

describe("GET /api/sbom/:scanId/spdx", () => {
  it("returns 401 without auth", async () => {
    const scanId = await seedScan();
    const res = await request.get(`/api/sbom/${scanId}/spdx`);
    expect(res.status).toBe(401);
  });

  it("returns 404 for unknown scan", async () => {
    const res = await request
      .get(`/api/sbom/${new ObjectId()}/spdx`)
      .set("Cookie", sessionCookie);
    expect(res.status).toBe(404);
  });

  it("returns SPDX format with spdxVersion field", async () => {
    const scanId = await seedScan([
      { endpoint: "https://spdx.example.com/api" },
    ]);

    const res = await request
      .get(`/api/sbom/${scanId}/spdx`)
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("spdxVersion");
    expect(res.body.spdxVersion).toBe("SPDX-2.3");
  });

  it("returns packages field as an array", async () => {
    const scanId = await seedScan([
      { endpoint: "https://pkg.example.com/route" },
    ]);

    const res = await request
      .get(`/api/sbom/${scanId}/spdx`)
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.packages)).toBe(true);
  });

  it("includes SPDXID and dataLicense fields", async () => {
    const scanId = await seedScan();

    const res = await request
      .get(`/api/sbom/${scanId}/spdx`)
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("SPDXID");
    expect(res.body.SPDXID).toBe("SPDXRef-DOCUMENT");
    expect(res.body).toHaveProperty("dataLicense");
    expect(res.body.dataLicense).toBe("CC0-1.0");
  });

  it("returns Content-Disposition attachment for SPDX", async () => {
    const scanId = await seedScan();

    const res = await request
      .get(`/api/sbom/${scanId}/spdx`)
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    const disposition = res.headers["content-disposition"] as string;
    expect(disposition.toLowerCase()).toContain("attachment");
    expect(disposition).toContain(".spdx.json");
  });
});
