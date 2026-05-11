import { col } from "./db";
import { ObjectId } from "mongodb";
import type { Request } from "express";

export async function auditFromReq(
  req: Request,
  action: string,
  resource?: string,
  resourceId?: string,
  details?: Record<string, unknown>
) {
  try {
    const session = req.session as Record<string, unknown>;
    await col("audit_log").insertOne({
      _id: new ObjectId(),
      user_id: session["userId"] ?? null,
      username: session["username"] ?? null,
      action,
      resource: resource ?? null,
      resource_id: resourceId ?? null,
      details: details ?? null,
      ip: req.ip ?? null,
      created_at: new Date(),
    });
  } catch {
    // audit failures are non-fatal
  }
}
