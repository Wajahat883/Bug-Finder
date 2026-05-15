import { Router } from "express";
import { col, ObjectId } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";
import { auditFromReq } from "../lib/audit";

const router = Router();

router.get("/gdpr/export", requireAuth, async (req, res) => {
  try {
    const sess = req.session as unknown as { userId?: string };
    const userId = sess.userId;
    if (!userId) return res.status(401).json({ error: "Not authenticated" });

    const [user, findings, scans, targets, apiKeys, notifPrefs, auditEntries, comments] = await Promise.all([
      col("users").findOne({ _id: new ObjectId(userId) } as Record<string, unknown>),
      col("findings").find({ user_id: userId } as Record<string, unknown>).limit(1000).toArray(),
      col("scan_jobs").find({ user_id: userId } as Record<string, unknown>).limit(200).toArray(),
      col("targets").find({ user_id: userId } as Record<string, unknown>).limit(200).toArray(),
      col("api_keys").find({ user_id: userId } as Record<string, unknown>).toArray(),
      col("notification_preferences").findOne({ user_id: userId } as Record<string, unknown>),
      col("audit_log").find({ user_id: userId } as Record<string, unknown>).sort({ created_at: -1 }).limit(500).toArray(),
      col("comments").find({ user_id: userId } as Record<string, unknown>).limit(500).toArray(),
    ]);

    const safeUser = { ...(user as Record<string, unknown> ?? {}), password: "[REDACTED]", totp_secret: "[REDACTED]", totp_secret_pending: "[REDACTED]" };

    const exportData = {
      export_date: new Date().toISOString(),
      user: safeUser,
      findings: (findings as Array<Record<string, unknown>>).map(f => ({ ...f, _id: String(f["_id"]) })),
      scan_jobs: (scans as Array<Record<string, unknown>>).map(s => ({ ...s, _id: String(s["_id"]) })),
      targets: (targets as Array<Record<string, unknown>>).map(t => ({ ...t, _id: String(t["_id"]) })),
      api_keys: (apiKeys as Array<Record<string, unknown>>).map(k => ({ id: String(k["_id"]), name: k["name"], key: "[REDACTED]", scopes: k["scopes"], created_at: k["created_at"] })),
      notification_preferences: notifPrefs,
      audit_log: (auditEntries as Array<Record<string, unknown>>).map(e => ({ ...e, _id: String(e["_id"]) })),
      comments: (comments as Array<Record<string, unknown>>).map(c => ({ ...c, _id: String(c["_id"]) })),
    };

    await auditFromReq(req, "gdpr.data_export", "users", userId);
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Content-Disposition", `attachment; filename="bugfinder-data-export-${userId}.json"`);
    res.json(exportData);
  } catch (err) {
    logger.error({ err }, "GDPR export error");
    res.status(500).json({ error: "Export failed" });
  }
});

export default router;
