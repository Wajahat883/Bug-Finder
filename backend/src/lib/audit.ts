import { col } from "./db";
import { ObjectId } from "mongodb";
import crypto from "crypto";
import type { Request } from "express";

// Lazy import to avoid circular dependency with anomaly-detector
async function runAnomalyCheck(event: Record<string, unknown>) {
  try {
    const { checkAnomaly } = await import("../services/anomaly-detector");
    await checkAnomaly(event as Parameters<typeof checkAnomaly>[0]);
  } catch { /* non-fatal */ }
}

// Compute hash chain: each entry hashes the previous entry's hash + current data
async function computeEntryHash(data: Record<string, unknown>): Promise<string> {
  try {
    const lastEntry = await col("audit_log").find({}).sort({ created_at: -1 }).limit(1).toArray() as Array<Record<string, unknown>>;
    const prevHash = lastEntry[0]?.["hash"] as string ?? "genesis";
    const content = prevHash + JSON.stringify({ action: data.action, user_id: data.user_id, resource_id: data.resource_id, created_at: data.created_at });
    return crypto.createHash("sha256").update(content).digest("hex");
  } catch {
    return crypto.createHash("sha256").update(JSON.stringify(data)).digest("hex");
  }
}

export async function logAudit(params: {
  userId: string;
  username: string;
  action: string;
  resource?: string;
  resourceId?: string;
  details?: Record<string, unknown>;
  ip?: string;
  before?: Record<string, unknown>;
  after?: Record<string, unknown>;
  userAgent?: string;
}) {
  try {
    const now = new Date();
    const entry: Record<string, unknown> = {
      _id: new ObjectId(),
      user_id: params.userId,
      username: params.username,
      action: params.action,
      resource: params.resource ?? null,
      resource_id: params.resourceId ?? null,
      details: params.details ?? null,
      ip: params.ip ?? null,
      user_agent: params.userAgent ?? null,
      created_at: now,
    };
    // Before/after field diffs for change tracking
    if (params.before !== undefined || params.after !== undefined) {
      entry["before"] = params.before ?? null;
      entry["after"] = params.after ?? null;
      // Compute diff: only changed fields
      if (params.before && params.after) {
        const diff: Record<string, { from: unknown; to: unknown }> = {};
        const allKeys = new Set([...Object.keys(params.before), ...Object.keys(params.after)]);
        for (const key of allKeys) {
          if (JSON.stringify(params.before[key]) !== JSON.stringify(params.after[key])) {
            diff[key] = { from: params.before[key], to: params.after[key] };
          }
        }
        entry["diff"] = diff;
      }
    }
    // Tamper-evident hash chain
    entry["hash"] = await computeEntryHash(entry);
    await col("audit_log").insertOne(entry);

    // Privilege escalation alert
    if (params.action === "user.role_change" || params.action === "role_grant.create") {
      try {
        const { sendEmail } = await import("../services/email");
        const settings = await col("settings").find({}).limit(1).toArray() as Array<Record<string, unknown>>;
        const adminEmail = process.env["ADMIN_EMAIL"] ?? settings[0]?.["admin_email"] as string ?? "";
        if (adminEmail) {
          sendEmail({
            to: adminEmail,
            subject: `[Security Alert] Privilege escalation: ${params.action}`,
            html: `<h3>Privilege Escalation Alert</h3><p>User <strong>${params.username}</strong> (${params.userId}) performed <strong>${params.action}</strong>.</p><p>Details: ${JSON.stringify(params.details ?? {})}</p><p>IP: ${params.ip ?? "unknown"}</p><p>Time: ${now.toISOString()}</p>`,
          }).catch(() => {});
        }
      } catch { /* non-fatal */ }
    }

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
  details?: Record<string, unknown>,
  before?: Record<string, unknown>,
  after?: Record<string, unknown>
) {
  try {
    const sess = req.session as unknown as { userId?: string; username?: string };
    const userId = String(sess.userId ?? "anonymous");
    const username = String(sess.username ?? "anonymous");
    const userAgent = req.headers["user-agent"] as string | undefined;
    await logAudit({ userId, username, action, resource, resourceId, details, ip: req.ip ?? undefined, before, after, userAgent });
  } catch {
    // audit failures are non-fatal
  }
}

// SIEM export: stream audit log entries in CEF (Common Event Format) for Splunk/ELK
export function formatAsCef(entry: Record<string, unknown>): string {
  const severity = ["user.login_failed", "role_grant.create", "user.role_change"].includes(String(entry["action"] ?? "")) ? "7" : "3";
  const ext = [
    `src=${entry["ip"] ?? "0.0.0.0"}`,
    `suser=${entry["username"] ?? "unknown"}`,
    `act=${entry["action"] ?? "unknown"}`,
    `cs1=${entry["resource_id"] ?? ""}`,
    `cs1Label=resourceId`,
    `rt=${entry["created_at"] instanceof Date ? entry["created_at"].getTime() : new Date(String(entry["created_at"] ?? "")).getTime()}`,
  ].join(" ");
  return `CEF:0|BugFinderPro|SecurityPlatform|1.0|${entry["action"] ?? "event"}|${entry["action"] ?? "event"}|${severity}|${ext}`;
}

// Verify hash chain integrity
export async function verifyAuditChain(limit = 100): Promise<{ valid: boolean; brokenAt?: string }> {
  try {
    const entries = await col("audit_log").find({}).sort({ created_at: 1 }).limit(limit).toArray() as Array<Record<string, unknown>>;
    let prevHash = "genesis";
    for (const entry of entries) {
      const { hash, ...data } = entry;
      const expected = crypto.createHash("sha256").update(prevHash + JSON.stringify({ action: data["action"], user_id: data["user_id"], resource_id: data["resource_id"], created_at: data["created_at"] })).digest("hex");
      if (hash !== expected) {
        return { valid: false, brokenAt: String(entry["_id"]) };
      }
      prevHash = String(hash);
    }
    return { valid: true };
  } catch {
    return { valid: false, brokenAt: "verification-error" };
  }
}
