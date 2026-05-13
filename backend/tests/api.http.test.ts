import { describe, it, expect, beforeAll, afterAll } from "vitest";
import supertest from "supertest";
import express, { type Express } from "express";
import session from "express-session";
import { MongoMemoryServer } from "mongodb-memory-server";

let app: Express;
let mongo: MongoMemoryServer;
let request: supertest.SuperTest<supertest.Test>;
let sessionCookie: string;

beforeAll(async () => {
  process.env["NODE_ENV"] = "test";
  process.env["SESSION_SECRET"] = "test-secret-key-32chars-minimum!";
  process.env["ADMIN_EMAIL"] = "admin@test.local";
  process.env["ADMIN_PASSWORD"] = "AdminP@ss123";

  const mod = await import("../src/app");
  app = mod.default;
  request = supertest(app);
}, 30000);

afterAll(async () => {
  // cleanup
});

describe("GET /api/health", () => {
  it("returns 200 with status ok", async () => {
    const res = await request.get("/api/health");
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("status");
    expect(res.body.status).toBe("ok");
  });

  it("returns JSON content-type", async () => {
    const res = await request.get("/api/health");
    expect(res.headers["content-type"]).toMatch(/application\/json/);
  });
});

describe("POST /api/auth/register", () => {
  const testEmail = `user-${Date.now()}@test.com`;

  it("rejects weak password (too short)", async () => {
    const res = await request.post("/api/auth/register").send({
      firstName: "Test", lastName: "User", email: testEmail, password: "12",
    });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("registers with valid data", async () => {
    const res = await request.post("/api/auth/register").send({
      firstName: "Test", lastName: "User", email: testEmail, password: "StrongP@ss1",
    });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty("id");
    expect(res.body.role).toBe("analyst");
  });

  it("rejects duplicate email", async () => {
    const res = await request.post("/api/auth/register").send({
      firstName: "Test", lastName: "User", email: testEmail, password: "AnotherP@ss1",
    });
    expect(res.status).toBe(409);
  });

  it("rejects missing fields", async () => {
    const res = await request.post("/api/auth/register").send({});
    expect(res.status).toBe(400);
  });
});

describe("POST /api/auth/login", () => {
  it("rejects invalid credentials", async () => {
    const res = await request.post("/api/auth/login").send({
      email: "nonexistent@test.com", password: "wrongpass",
    });
    expect(res.status).toBe(401);
  });

  it("rejects empty body", async () => {
    const res = await request.post("/api/auth/login").send({});
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });
});

describe("GET /api/auth/me", () => {
  it("returns 401 without session", async () => {
    const res = await request.get("/api/auth/me");
    expect(res.status).toBe(401);
  });
});

describe("GET /api/scan-jobs", () => {
  it("returns 401 without auth", async () => {
    const res = await request.get("/api/scan-jobs");
    expect(res.status).toBe(401);
  });
});

describe("GET /api/findings", () => {
  it("returns 401 without auth", async () => {
    const res = await request.get("/api/findings");
    expect(res.status).toBe(401);
  });
});

describe("GET /api/settings", () => {
  it("returns 401 without auth", async () => {
    const res = await request.get("/api/settings");
    expect(res.status).toBe(401);
  });
});

describe("GET /api/analytics/dashboard", () => {
  it("returns 401 without auth", async () => {
    const res = await request.get("/api/analytics/dashboard");
    expect(res.status).toBe(401);
  });
});

describe("POST /api/auth/forgot-password", () => {
  it("returns 200 for any email (no user enumeration)", async () => {
    const res = await request.post("/api/auth/forgot-password").send({ email: "exists@test.com" });
    expect(res.status).toBe(200);
  });

  it("returns 400 without email field", async () => {
    const res = await request.post("/api/auth/forgot-password").send({});
    expect(res.status).toBe(400);
  });
});

describe("GET /api/auth/oauth/google", () => {
  it("returns 400 when Google OAuth not configured", async () => {
    const res = await request.get("/api/auth/oauth/google");
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/not configured/i);
  });
});

describe("GET /api/auth/oauth/github", () => {
  it("returns 400 when GitHub OAuth not configured", async () => {
    const res = await request.get("/api/auth/oauth/github");
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/not configured/i);
  });
});

describe("404 handler", () => {
  it("returns 404 JSON for unknown routes", async () => {
    const res = await request.get("/api/nonexistent-route-xyz");
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty("error");
  });
});

describe("Security", () => {
  it("rejects SQL-injection in query params safely", async () => {
    const res = await request.get("/api/findings?severity=' OR '1'='1");
    expect(res.status).toBeLessThan(500);
  });

  it("rejects large payloads without crashing", async () => {
    const res = await request.post("/api/auth/login").send({
      email: "x".repeat(50000), password: "y".repeat(50000),
    });
    expect(res.status).toBeLessThan(500);
  });
});
