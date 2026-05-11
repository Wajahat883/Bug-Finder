import type { Request, Response, NextFunction } from "express";
import { col } from "../lib/db";

interface SessionData {
  userId?: string;
  username?: string;
  role?: string;
}

// Allows requests authenticated via X-API-Key header to bypass session auth.
// Sets req.session fields so downstream routes see a valid session.
export async function apiKeyAuth(req: Request, res: Response, next: NextFunction) {
  const key = req.headers["x-api-key"] as string | undefined;
  if (!key) { next(); return; }

  const settings = (await col("settings").findOne({})) as Record<string, unknown> | null;
  if (!settings || settings["api_key"] !== key) {
    res.status(401).json({ error: "Invalid API key" });
    return;
  }

  // Inject a synthetic session so RBAC and audit middleware work
  const session = (req as unknown as { session: SessionData }).session;
  session.userId = "api_key_user";
  session.username = "api_key";
  session.role = "admin";
  next();
}
