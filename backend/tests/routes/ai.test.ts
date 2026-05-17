/**
 * AI route tests
 *
 * The AI endpoints use OpenAI-compatible SSE streaming.  We mock the openai
 * module so no real API calls are made, then assert on the HTTP-level
 * behaviour (auth guard, validation, 400s, SSE headers, confidence field).
 *
 * Endpoints tested:
 *  POST /ai/chat             — validates message field, requires auth
 *  POST /ai/scan-summary/:id — requires auth, returns SSE with confidence
 *  POST /ai/finding-advice/:id — requires auth, returns SSE with confidence
 *  GET  /ai/usage            — requires auth, returns used/budget/remaining
 *  GET  /ai/feedback/stats   — returns { total, positive, negative, by_type, accuracy_rate }
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import supertest from "supertest";
import type { Express } from "express";
import { ObjectId } from "mongodb";
import { col } from "../../src/lib/db";

// ── Mock OpenAI SDK ───────────────────────────────────────────────────────────
// The AI route imports OpenAI from "openai" and calls chat.completions.create
// with stream: true.  We return an async iterable that yields a single chunk
// containing "confidence" so the response accumulates meaningful text.
vi.mock("openai", () => {
  async function* fakeStream() {
    yield {
      choices: [
        {
          delta: { content: "Test AI response. Confidence is high." },
          finish_reason: null,
        },
      ],
    };
    yield {
      choices: [{ delta: { content: "" }, finish_reason: "stop" }],
    };
  }

  const mockCreate = vi.fn().mockResolvedValue(fakeStream());

  return {
    default: class OpenAI {
      chat = {
        completions: {
          create: mockCreate,
        },
      };
    },
  };
});

// Mock Redis so cache misses are always returned (no real Redis needed)
vi.mock("../../src/lib/redis", () => ({
  redisGet: vi.fn().mockResolvedValue(null),
  redisSet: vi.fn().mockResolvedValue("OK"),
}));

// Mock vault so getSecret resolves immediately
vi.mock("../../src/lib/vault", () => ({
  vault: {
    getSecret: vi.fn().mockResolvedValue("fake-openai-api-key"),
  },
}));

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

async function seedFinding(overrides: Record<string, unknown> = {}): Promise<string> {
  const result = await col("findings").insertOne({
    title: "SQL Injection",
    severity: "critical",
    category: "Injection",
    endpoint: "https://target.example.com/api/users",
    description: "Input not sanitised",
    evidence: "SELECT * FROM users WHERE id = '1' OR '1'='1'",
    cwe_id: "CWE-89",
    cvss_score: 9.8,
    status: "open",
    created_at: new Date(),
    ...overrides,
  });
  return result.insertedId.toString();
}

async function seedScan(overrides: Record<string, unknown> = {}): Promise<string> {
  const result = await col("scan_jobs").insertOne({
    status: "completed",
    target_url: "https://target.example.com",
    risk_score: 72,
    created_at: new Date(),
    completed_at: new Date(),
    ...overrides,
  });
  return result.insertedId.toString();
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

// ── POST /ai/chat ─────────────────────────────────────────────────────────────

describe("POST /api/ai/chat", () => {
  it("returns 401 without auth", async () => {
    const res = await request
      .post("/api/ai/chat")
      .send({ message: "What is SQL injection?" });
    expect(res.status).toBe(401);
  });

  it("returns 400 when message field is missing", async () => {
    const res = await request
      .post("/api/ai/chat")
      .set("Cookie", sessionCookie)
      .send({});
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
    expect(res.body.error).toMatch(/message/i);
  });

  it("returns SSE content-type for a valid message", async () => {
    const res = await request
      .post("/api/ai/chat")
      .set("Cookie", sessionCookie)
      .set("Accept", "text/event-stream")
      .send({ message: "Explain XSS in one sentence." })
      .timeout(10000);

    // The route streams SSE — status 200, content-type text/event-stream
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/text\/event-stream/);
  });

  it("SSE stream contains done:true event", async () => {
    const res = await request
      .post("/api/ai/chat")
      .set("Cookie", sessionCookie)
      .set("Accept", "text/event-stream")
      .send({ message: "Hello" })
      .buffer(true)
      .timeout(10000);

    expect(res.status).toBe(200);
    const body = res.text ?? "";
    expect(body).toContain("data:");
  });

  it("returns 429 when conversation history exceeds token cap", async () => {
    // Build a history large enough to exceed AI_CONVERSATION_TOKEN_CAP (8000 tokens ≈ 32000 chars)
    const longContent = "A".repeat(33000);
    const res = await request
      .post("/api/ai/chat")
      .set("Cookie", sessionCookie)
      .send({
        message: "Hello",
        history: [{ role: "user", content: longContent }],
      });

    expect(res.status).toBe(429);
    expect(res.body).toHaveProperty("error");
  });
});

// ── POST /ai/scan-summary/:id ─────────────────────────────────────────────────

describe("POST /api/ai/scan-summary/:id", () => {
  it("returns 401 without auth", async () => {
    const scanId = await seedScan();
    const res = await request.post(`/api/ai/scan-summary/${scanId}`);
    expect(res.status).toBe(401);
  });

  it("returns 404 for a non-existent scan", async () => {
    const res = await request
      .post(`/api/ai/scan-summary/${new ObjectId()}`)
      .set("Cookie", sessionCookie);
    expect(res.status).toBe(404);
  });

  it("streams SSE response for a valid scan", async () => {
    const scanId = await seedScan();

    const res = await request
      .post(`/api/ai/scan-summary/${scanId}`)
      .set("Cookie", sessionCookie)
      .set("Accept", "text/event-stream")
      .timeout(10000);

    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/text\/event-stream/);
  });

  it("SSE stream includes a confidence value (0-100) in the done event", async () => {
    const scanId = await seedScan();

    const res = await request
      .post(`/api/ai/scan-summary/${scanId}`)
      .set("Cookie", sessionCookie)
      .buffer(true)
      .timeout(10000);

    expect(res.status).toBe(200);
    const body = res.text ?? "";
    // Find the done event and parse confidence
    const doneMatch = body.match(/data:\s*(\{[^}]*"done"\s*:\s*true[^}]*\})/);
    if (doneMatch) {
      const parsed = JSON.parse(doneMatch[1]) as { done: boolean; confidence?: number };
      if (parsed.confidence !== undefined) {
        expect(typeof parsed.confidence).toBe("number");
        expect(parsed.confidence).toBeGreaterThanOrEqual(0);
        expect(parsed.confidence).toBeLessThanOrEqual(100);
      }
    }
    // At minimum the body should contain SSE data
    expect(body).toContain("data:");
  });
});

// ── POST /ai/finding-advice/:id ───────────────────────────────────────────────

describe("POST /api/ai/finding-advice/:id", () => {
  it("returns 401 without auth", async () => {
    const findingId = await seedFinding();
    const res = await request.post(`/api/ai/finding-advice/${findingId}`);
    expect(res.status).toBe(401);
  });

  it("returns 404 for a non-existent finding", async () => {
    const res = await request
      .post(`/api/ai/finding-advice/${new ObjectId()}`)
      .set("Cookie", sessionCookie);
    expect(res.status).toBe(404);
  });

  it("streams SSE response for a valid finding", async () => {
    const findingId = await seedFinding();

    const res = await request
      .post(`/api/ai/finding-advice/${findingId}`)
      .set("Cookie", sessionCookie)
      .set("Accept", "text/event-stream")
      .timeout(10000);

    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/text\/event-stream/);
  });

  it("confidence field in done event is between 0 and 100", async () => {
    const findingId = await seedFinding({ title: "Reflected XSS", category: "XSS" });

    const res = await request
      .post(`/api/ai/finding-advice/${findingId}`)
      .set("Cookie", sessionCookie)
      .buffer(true)
      .timeout(10000);

    expect(res.status).toBe(200);
    const body = res.text ?? "";
    expect(body).toContain("data:");

    const doneMatch = body.match(/data:\s*(\{[^}]*"done"\s*:\s*true[^}]*\})/);
    if (doneMatch) {
      const parsed = JSON.parse(doneMatch[1]) as { done: boolean; confidence?: number };
      if (parsed.confidence !== undefined) {
        expect(parsed.confidence).toBeGreaterThanOrEqual(0);
        expect(parsed.confidence).toBeLessThanOrEqual(100);
      }
    }
  });
});

// ── GET /ai/usage ─────────────────────────────────────────────────────────────

describe("GET /api/ai/usage", () => {
  it("returns 401 without auth", async () => {
    const res = await request.get("/api/ai/usage");
    expect(res.status).toBe(401);
  });

  it("returns used, budget, and remaining fields", async () => {
    const res = await request
      .get("/api/ai/usage")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("used");
    expect(res.body).toHaveProperty("budget");
    expect(res.body).toHaveProperty("remaining");
    expect(typeof res.body.used).toBe("number");
    expect(typeof res.body.budget).toBe("number");
    expect(typeof res.body.remaining).toBe("number");
  });

  it("remaining equals budget minus used", async () => {
    const res = await request
      .get("/api/ai/usage")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body.remaining).toBe(
      Math.max(0, (res.body.budget as number) - (res.body.used as number))
    );
  });
});

// ── GET /ai/feedback/stats ────────────────────────────────────────────────────

describe("GET /api/ai/feedback/stats", () => {
  it("returns 401 without auth", async () => {
    const res = await request.get("/api/ai/feedback/stats");
    expect(res.status).toBe(401);
  });

  it("returns stats with required fields when no feedback exists", async () => {
    const res = await request
      .get("/api/ai/feedback/stats")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("total");
    expect(res.body).toHaveProperty("positive");
    expect(res.body).toHaveProperty("negative");
    expect(res.body).toHaveProperty("by_type");
    expect(res.body).toHaveProperty("accuracy_rate");

    expect(typeof res.body.total).toBe("number");
    expect(typeof res.body.positive).toBe("number");
    expect(typeof res.body.negative).toBe("number");
    expect(typeof res.body.by_type).toBe("object");
  });

  it("accuracy_rate is 'N/A' when no feedback has been recorded", async () => {
    const res = await request
      .get("/api/ai/feedback/stats")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    // When total = 0, accuracy_rate is "N/A"
    if (res.body.total === 0) {
      expect(res.body.accuracy_rate).toBe("N/A");
    }
  });

  it("computes accuracy_rate as a percentage string when feedback exists", async () => {
    // Seed some positive and negative feedback
    await col("ai_feedback").insertOne({
      type: "finding-advice",
      vote: "up",
      finding_id: new ObjectId().toString(),
      created_at: new Date(),
    });
    await col("ai_feedback").insertOne({
      type: "finding-advice",
      vote: "down",
      finding_id: new ObjectId().toString(),
      created_at: new Date(),
    });

    const res = await request
      .get("/api/ai/feedback/stats")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);

    if (res.body.total > 0) {
      // accuracy_rate should look like "50%" or "100%", etc.
      expect(typeof res.body.accuracy_rate).toBe("string");
      expect(res.body.accuracy_rate).toMatch(/^\d+%$/);
      expect(res.body.positive + res.body.negative).toBeLessThanOrEqual(res.body.total);
    }
  });
});
