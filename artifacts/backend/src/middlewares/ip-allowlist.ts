import type { Request, Response, NextFunction } from "express";
import { col } from "../lib/db";

let cachedAllowlist: string[] | null = null;
let cacheExpiry = 0;

async function getAllowlist(): Promise<string[]> {
  if (cachedAllowlist && Date.now() < cacheExpiry) return cachedAllowlist;
  try {
    const settings = await col("settings").findOne({ key: "ip_allowlist" }) as Record<string,unknown> | null;
    cachedAllowlist = settings?.["value"] ? String(settings["value"]).split("\n").map(s => s.trim()).filter(Boolean) : [];
    cacheExpiry = Date.now() + 60000;
    return cachedAllowlist;
  } catch { return []; }
}

export async function ipAllowlistMiddleware(req: Request, res: Response, next: NextFunction) {
  const allowlist = await getAllowlist();
  if (!allowlist.length) return next(); // no restrictions if list is empty
  const ip = String(req.ip ?? req.socket.remoteAddress ?? "");
  const clientIp = ip.replace("::ffff:", "");
  if (allowlist.some(a => clientIp === a || clientIp.startsWith(a))) return next();
  res.status(403).json({ error: "Access denied from your IP address" });
}
