/**
 * Audit Log Anomaly Detector — runs on every audit event and fires alerts when
 * suspicious patterns are detected.
 *
 * Rules:
 *  1. Bulk delete: >10 delete actions in 60s by same user
 *  2. Rapid fire: >50 events of any kind in 5min by same user
 *  3. Repeated login failure: >5 failed logins in 10min
 *  4. Privilege escalation attempt: role change event
 *  5. After-hours login: login between 00:00-05:00 UTC
 */
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { sendEmail } from "./email";

export interface AuditEvent {
  userId?: string;
  username?: string;
  action: string;
  resource?: string;
  resourceId?: string;
  ip?: string;
  details?: Record<string, unknown>;
  [key: string]: unknown;
}

// In-memory sliding window counters (flushed on restart — Redis for production)
const counters = new Map<string, number[]>();

function getWindow(key: string, windowMs: number): number {
  const now = Date.now();
  const times = (counters.get(key) ?? []).filter(t => t > now - windowMs);
  times.push(now);
  counters.set(key, times);
  return times.length;
}

async function fireAlert(type: string, userId: string | undefined, details: Record<string, unknown>): Promise<void> {
  try {
    await col("anomaly_alerts").insertOne({
      type,
      user_id: userId,
      details,
      created_at: new Date(),
      acknowledged: false,
    });

    const adminEmail = process.env["ADMIN_EMAIL"] ?? "admin@bugfinder.local";
    await sendEmail({
      to: adminEmail,
      subject: `[BugFinder Security Alert] ${type}`,
      html: `
        <h2 style="color:#ef4444">Security Anomaly Detected</h2>
        <p><strong>Type:</strong> ${type}</p>
        <p><strong>User ID:</strong> ${userId ?? "unknown"}</p>
        <p><strong>Time:</strong> ${new Date().toISOString()}</p>
        <pre style="background:#1e1e1e;color:#d4d4d4;padding:12px;border-radius:6px">${JSON.stringify(details, null, 2)}</pre>
        <p>Review the audit log in the BugFinder admin panel for details.</p>
      `,
    });
  } catch (err) {
    logger.error({ err }, "Anomaly alert delivery failed");
  }
}

export async function checkAnomaly(event: AuditEvent): Promise<void> {
  const { userId, username, action, ip } = event;
  const key = userId ?? ip ?? "anon";

  // Rule 1: Bulk delete
  if (action.includes("delete") || action.includes("remove")) {
    const count = getWindow(`delete:${key}`, 60_000);
    if (count === 10) {
      await fireAlert("BULK_DELETE", userId, { count, username, ip, action });
    }
  }

  // Rule 2: Rapid fire — >50 events in 5min
  const total = getWindow(`total:${key}`, 5 * 60_000);
  if (total === 50) {
    await fireAlert("RAPID_FIRE_EVENTS", userId, { count: total, username, ip });
  }

  // Rule 3: Repeated login failure
  if (action === "user.login_failed") {
    const fails = getWindow(`login_fail:${key}`, 10 * 60_000);
    if (fails === 5) {
      await fireAlert("REPEATED_LOGIN_FAILURE", userId, { count: fails, ip, username });
    }
  }

  // Rule 4: Privilege escalation
  if (action === "user.role_change" || action === "admin.role_update") {
    await fireAlert("PRIVILEGE_ESCALATION", userId, event.details ?? {});
  }

  // Rule 5: After-hours login (00:00–05:00 UTC)
  if (action === "user.login") {
    const hour = new Date().getUTCHours();
    if (hour >= 0 && hour < 5) {
      await fireAlert("AFTER_HOURS_LOGIN", userId, { hour, ip, username });
    }
  }
}
