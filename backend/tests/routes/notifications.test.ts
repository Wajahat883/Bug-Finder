/**
 * Notification route tests
 * GET    /notifications
 * GET    /notifications/unread-count
 * POST   /notifications/mark-all-read
 * POST   /notifications/read-all
 * PATCH  /notifications/:id/read
 * DELETE /notifications/:id
 * GET    /notifications/preferences
 * PUT    /notifications/preferences
 * POST   /notifications/digest
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import supertest from "supertest";
import type { Express } from "express";
import { ObjectId } from "mongodb";
import { col } from "../../src/lib/db";

// Mock sendEmail so no real SMTP calls happen
vi.mock("../../src/services/email", () => ({
  sendEmail: vi.fn().mockResolvedValue(undefined),
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

// Helper to insert a notification
async function insertNotification(overrides: Record<string, unknown> = {}): Promise<ObjectId> {
  const result = await col("notifications").insertOne({
    type: "finding",
    title: "Test Notification",
    message: "A test notification",
    read: false,
    created_at: new Date(),
    ...overrides,
  });
  return result.insertedId;
}

// ── GET /notifications ────────────────────────────────────────────────────────

describe("GET /api/notifications", () => {
  it("returns 401 without auth", async () => {
    const res = await request.get("/api/notifications");
    expect(res.status).toBe(401);
  });

  it("returns an array of notifications for the current user", async () => {
    await insertNotification({ title: "User Notification" });

    const res = await request
      .get("/api/notifications")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  it("each notification has required shape fields", async () => {
    await insertNotification({ title: "Shape Check" });

    const res = await request
      .get("/api/notifications")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);

    if (res.body.length > 0) {
      const n = res.body[0] as Record<string, unknown>;
      expect(n).toHaveProperty("id");
      expect(n).toHaveProperty("type");
      expect(n).toHaveProperty("title");
      expect(n).toHaveProperty("message");
      expect(n).toHaveProperty("read");
    }
  });
});

// ── GET /notifications/unread-count ──────────────────────────────────────────

describe("GET /api/notifications/unread-count", () => {
  it("returns 401 without auth", async () => {
    const res = await request.get("/api/notifications/unread-count");
    expect(res.status).toBe(401);
  });

  it("returns an object with a numeric count field", async () => {
    await insertNotification({ read: false });

    const res = await request
      .get("/api/notifications/unread-count")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("count");
    expect(typeof res.body.count).toBe("number");
    expect(res.body.count).toBeGreaterThanOrEqual(0);
  });

  it("count reflects unread notifications", async () => {
    // Mark everything read first
    await request
      .post("/api/notifications/mark-all-read")
      .set("Cookie", sessionCookie);

    // Insert two unread
    await insertNotification({ read: false });
    await insertNotification({ read: false });

    const res = await request
      .get("/api/notifications/unread-count")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body.count).toBeGreaterThanOrEqual(2);
  });
});

// ── POST /notifications/mark-all-read ────────────────────────────────────────

describe("POST /api/notifications/mark-all-read", () => {
  it("returns 401 without auth", async () => {
    const res = await request.post("/api/notifications/mark-all-read");
    expect(res.status).toBe(401);
  });

  it("updates all unread notifications to read: true", async () => {
    await insertNotification({ read: false, title: "Unread A" });
    await insertNotification({ read: false, title: "Unread B" });

    const res = await request
      .post("/api/notifications/mark-all-read")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);

    const countRes = await request
      .get("/api/notifications/unread-count")
      .set("Cookie", sessionCookie);

    expect(countRes.body.count).toBe(0);
  });
});

// ── POST /notifications/read-all ─────────────────────────────────────────────

describe("POST /api/notifications/read-all", () => {
  it("returns 401 without auth", async () => {
    const res = await request.post("/api/notifications/read-all");
    expect(res.status).toBe(401);
  });

  it("behaves identically to mark-all-read", async () => {
    await insertNotification({ read: false, title: "Alias Test" });

    const res = await request
      .post("/api/notifications/read-all")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);

    const countRes = await request
      .get("/api/notifications/unread-count")
      .set("Cookie", sessionCookie);
    expect(countRes.body.count).toBe(0);
  });
});

// ── PATCH /notifications/:id/read ────────────────────────────────────────────

describe("PATCH /api/notifications/:id/read", () => {
  it("returns 401 without auth", async () => {
    const id = await insertNotification();
    const res = await request.patch(`/api/notifications/${id}/read`);
    expect(res.status).toBe(401);
  });

  it("returns 404 for invalid ObjectId", async () => {
    const res = await request
      .patch("/api/notifications/not-a-valid-id/read")
      .set("Cookie", sessionCookie);
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty("error");
  });

  it("marks a single notification as read", async () => {
    const id = await insertNotification({ read: false });

    const res = await request
      .patch(`/api/notifications/${id}/read`)
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it("returns 200 even for a non-existent (but valid) ObjectId", async () => {
    const res = await request
      .patch(`/api/notifications/${new ObjectId()}/read`)
      .set("Cookie", sessionCookie);

    // Route does updateOne which is a no-op for missing docs — still 200
    expect(res.status).toBe(200);
  });
});

// ── DELETE /notifications/:id ─────────────────────────────────────────────────

describe("DELETE /api/notifications/:id", () => {
  it("returns 401 without auth", async () => {
    const id = await insertNotification();
    const res = await request.delete(`/api/notifications/${id}`);
    expect(res.status).toBe(401);
  });

  it("returns 404 for invalid ObjectId", async () => {
    const res = await request
      .delete("/api/notifications/bad-id")
      .set("Cookie", sessionCookie);
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty("error");
  });

  it("deletes the notification and returns ok", async () => {
    const id = await insertNotification({ title: "To Delete" });

    const res = await request
      .delete(`/api/notifications/${id}`)
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });
});

// ── GET /notifications/preferences ───────────────────────────────────────────

describe("GET /api/notifications/preferences", () => {
  it("returns 401 without auth", async () => {
    const res = await request.get("/api/notifications/preferences");
    expect(res.status).toBe(401);
  });

  it("returns preferences with defaults when none are stored", async () => {
    const res = await request
      .get("/api/notifications/preferences")
      .set("Cookie", sessionCookie);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("channels");
    expect(res.body).toHaveProperty("notify_critical");
    expect(res.body).toHaveProperty("notify_high");
    expect(res.body).toHaveProperty("notify_scan_complete");

    // Defaults
    expect(Array.isArray(res.body.channels)).toBe(true);
    expect(res.body.notify_critical).toBe(true);
    expect(res.body.notify_high).toBe(true);
  });
});

// ── PUT /notifications/preferences ───────────────────────────────────────────

describe("PUT /api/notifications/preferences", () => {
  it("returns 401 without auth", async () => {
    const res = await request
      .put("/api/notifications/preferences")
      .send({ channels: ["email"] });
    expect(res.status).toBe(401);
  });

  it("returns 400 when channels contains an invalid enum value", async () => {
    const res = await request
      .put("/api/notifications/preferences")
      .set("Cookie", sessionCookie)
      .send({ channels: ["email", "invalid_channel"] });

    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("updates preferences with valid channels", async () => {
    const res = await request
      .put("/api/notifications/preferences")
      .set("Cookie", sessionCookie)
      .send({
        channels: ["email", "slack"],
        notify_critical: true,
        notify_high: false,
        notify_scan_complete: true,
      });

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);

    // Verify the changes persisted
    const getRes = await request
      .get("/api/notifications/preferences")
      .set("Cookie", sessionCookie);

    expect(getRes.status).toBe(200);
    expect(getRes.body.channels).toContain("email");
    expect(getRes.body.channels).toContain("slack");
  });

  it("accepts all valid channel enum values", async () => {
    const res = await request
      .put("/api/notifications/preferences")
      .set("Cookie", sessionCookie)
      .send({ channels: ["email", "slack", "teams", "pagerduty"] });

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });
});

// ── POST /notifications/digest ────────────────────────────────────────────────

describe("POST /api/notifications/digest", () => {
  it("returns 401 without auth", async () => {
    const res = await request
      .post("/api/notifications/digest")
      .send({ email: "test@example.com" });
    expect(res.status).toBe(401);
  });

  it("returns 400 for invalid email", async () => {
    const res = await request
      .post("/api/notifications/digest")
      .set("Cookie", sessionCookie)
      .send({ email: "not-an-email" });

    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("returns 400 when email field is missing", async () => {
    const res = await request
      .post("/api/notifications/digest")
      .set("Cookie", sessionCookie)
      .send({});

    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("sends digest for a valid email", async () => {
    const res = await request
      .post("/api/notifications/digest")
      .set("Cookie", sessionCookie)
      .send({ email: "security@example.com" });

    // 200 regardless of whether SMTP is configured (ok: true or ok: false with html)
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("ok");
  });

  it("applies rate limit after 5 requests", async () => {
    // Send 5 successful requests
    for (let i = 0; i < 5; i++) {
      await request
        .post("/api/notifications/digest")
        .set("Cookie", sessionCookie)
        .send({ email: `rate${i}@example.com` });
    }

    // The 6th should be rate-limited (429)
    const res = await request
      .post("/api/notifications/digest")
      .set("Cookie", sessionCookie)
      .send({ email: "rate6@example.com" });

    expect(res.status).toBe(429);
  });
});
