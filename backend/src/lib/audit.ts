import { col } from "./db";
import { ObjectId } from "mongodb";
import type { Request } from "express";

// Lazy import to avoid circular dependency with anomaly-detector
async function runAnomalyCheck(event: Record<string, unknown>) {
  try {
    const { checkAnomaly } = await import("../services/anomaly-detector");
    await checkAnomaly(event as Parameters<typeof checkAnomaly>[0]);
  } catch { /* non-fatal */ }
}

export async function logAudit(params: {
  userId: string;
  username: string;
  action: string;
  resource?: string;
  resourceId?: string;
  details?: Record<string, unknown>;
  ip?: string;
}) {
  try {
    await col("audit_log").insertOne({
      _id: new ObjectId(),
      user_id: params.userId,
      username: params.username,
      action: params.action,
      resource: params.resource ?? null,
      resource_id: params.resourceId ?? null,
      details: params.details ?? null,
      ip: params.ip ?? null,
      created_at: new Date(),
    });
    // Async anomaly check — never blocks the request
    void runAnomalyCheck(params as unknown as Record<string, unknown>);
  } catch {
    // audit failures are non-fatal
  }
}

export async function auditFromReq(
  req: Request,
  action: string,
  resource?: string,
  resourceId?: string,
  details?: Record<string, unknown>
) {
  try {
    const sess = req.session as unknown as { userId?: string; username?: string };
    const userId = String(sess.userId ?? "anonymous");
    const username = String(sess.username ?? "anonymous");
    await logAudit({ userId, username, action, resource, resourceId, details, ip: req.ip ?? undefined });
  } catch {
    // audit failures are non-fatal
  }
}
