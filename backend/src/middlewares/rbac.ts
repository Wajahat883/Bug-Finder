import type { Request, Response, NextFunction } from "express";
import { col } from "../lib/db";
import { ObjectId } from "mongodb";

interface SessionData {
  userId?: string;
  role?: string;
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const session = (req as unknown as { session: SessionData }).session;
  if (!session?.userId) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }
  next();
}

export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const session = (req as unknown as { session: SessionData }).session;
    if (!session?.userId) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }
    if (!roles.includes(session.role ?? "")) {
      res.status(403).json({ error: "Insufficient permissions" });
      return;
    }
    next();
  };
}

export const requireAdmin = requireRole("admin");

// API key scope enforcement middleware
// Usage: requireApiKeyScope("scan") — validates X-API-Key header has required scope
export function requireApiKeyScope(scope: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const apiKey = req.headers["x-api-key"] as string | undefined;
    if (!apiKey) {
      // Fall through to session auth if no API key provided
      next();
      return;
    }
    try {
      const keyDoc = await col("api_keys").findOne({ key: apiKey, active: true } as Record<string, unknown>) as Record<string, unknown> | null;
      if (!keyDoc) {
        res.status(401).json({ error: "Invalid or inactive API key" });
        return;
      }
      const scopes = (keyDoc["scopes"] as string[]) ?? [];
      if (!scopes.includes(scope) && !scopes.includes("admin")) {
        res.status(403).json({ error: `API key missing required scope: ${scope}` });
        return;
      }
      // Stamp usage
      col("api_keys").updateOne(
        { _id: keyDoc["_id"] } as Record<string, unknown>,
        { $set: { last_used: new Date() }, $inc: { usage_count: 1 } } as Record<string, unknown>
      ).catch(() => {});
      // Inject synthetic session so downstream handlers work
      const sess = (req as unknown as { session: SessionData }).session;
      sess.userId = String(keyDoc["user_id"] ?? "api");
      sess.role = scopes.includes("admin") ? "admin" : "analyst";
      next();
    } catch {
      res.status(500).json({ error: "API key validation failed" });
    }
  };
}

// Authenticate via API key OR session — whichever is present
export async function requireAuthOrApiKey(req: Request, res: Response, next: NextFunction) {
  const session = (req as unknown as { session: SessionData }).session;
  if (session?.userId) { next(); return; }

  const apiKey = req.headers["x-api-key"] as string | undefined;
  if (!apiKey) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }
  try {
    const keyDoc = await col("api_keys").findOne({ key: apiKey, active: true } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!keyDoc) {
      res.status(401).json({ error: "Invalid or inactive API key" });
      return;
    }
    col("api_keys").updateOne(
      { _id: keyDoc["_id"] } as Record<string, unknown>,
      { $set: { last_used: new Date() }, $inc: { usage_count: 1 } } as Record<string, unknown>
    ).catch(() => {});
    session.userId = String(keyDoc["user_id"] ?? "api");
    const scopes = (keyDoc["scopes"] as string[]) ?? [];
    session.role = scopes.includes("admin") ? "admin" : "analyst";
    next();
  } catch {
    res.status(500).json({ error: "Authentication failed" });
  }
}

// Time-boxed role grants — check if user has an active temporary grant
export async function checkTemporaryGrant(userId: string, requiredRole: string): Promise<boolean> {
  try {
    const now = new Date();
    const grant = await col("role_grants").findOne({
      user_id: userId,
      role: requiredRole,
      expires_at: { $gt: now },
      active: true,
    } as Record<string, unknown>);
    return !!grant;
  } catch {
    return false;
  }
}

// Middleware that allows access if user has role OR has active temporary grant
export function requireRoleOrGrant(...roles: string[]) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const session = (req as unknown as { session: SessionData }).session;
    if (!session?.userId) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }
    if (roles.includes(session.role ?? "")) { next(); return; }
    // Check temporary grants
    for (const role of roles) {
      if (await checkTemporaryGrant(session.userId, role)) { next(); return; }
    }
    res.status(403).json({ error: "Insufficient permissions" });
  };
}

// Field-level access control — strip fields from response based on role
export function filterFieldsByRole(data: Record<string, unknown>, role: string): Record<string, unknown> {
  const viewerHidden = ["evidence", "raw_request", "raw_response"];
  const analystHidden: string[] = [];

  if (role === "viewer") {
    const filtered = { ...data };
    for (const field of viewerHidden) delete filtered[field];
    return filtered;
  }
  if (role === "analyst") {
    const filtered = { ...data };
    for (const field of analystHidden) delete filtered[field];
    return filtered;
  }
  return data;
}
