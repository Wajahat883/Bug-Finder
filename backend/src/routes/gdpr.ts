import { Router } from "express";
import { col, ObjectId } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";
import { auditFromReq } from "../lib/audit";

const router = Router();

// GET /gdpr/export — full GDPR data export for the authenticated user
router.get("/gdpr/export", requireAuth, async (req, res) => {
  try {
    const sess = req.session as unknown as { userId?: string };
    const userId = sess.userId;
    if (!userId) return res.status(401).json({ error: "Not authenticated" });

    const userFilter = { user_id: userId } as Record<string, unknown>;
    const [
      user,
      findings,
      scans,
      auditEntries,
      notifications,
      apiKeys,
      notifPrefs,
      totalFindings,
    ] = await Promise.all([
      col("users").findOne({ _id: new ObjectId(userId) } as Record<string, unknown>),
      col("findings").find(userFilter).limit(5000).toArray(),
      col("scan_jobs").find(userFilter).limit(500).toArray(),
      col("audit_log").find(userFilter).sort({ created_at: -1 }).limit(1000).toArray(),
      col("notifications").find(userFilter).sort({ created_at: -1 }).limit(500).toArray(),
      col("api_keys").find(userFilter).toArray(),
      col("notification_preferences").findOne(userFilter),
      col("findings").countDocuments(userFilter),
    ]);

    const safeUser = {
      ...(user as Record<string, unknown> ?? {}),
      password: "[REDACTED]",
      totp_secret: "[REDACTED]",
      totp_secret_pending: "[REDACTED]",
    };

    const dateStr = new Date().toISOString().slice(0, 10);
    const exportData = {
      generated_at: new Date().toISOString(),
      user: { ...safeUser, _id: String((safeUser as Record<string, unknown>)["_id"]) },
      scan_jobs: (scans as Array<Record<string, unknown>>).map(s => ({ ...s, _id: String(s["_id"]) })),
      findings: (findings as Array<Record<string, unknown>>).map(f => ({ ...f, _id: String(f["_id"]) })),
      findings_note: totalFindings > 5000 ? `Only the first 5000 of ${totalFindings} findings are included in this export.` : undefined,
      audit_log: (auditEntries as Array<Record<string, unknown>>).map(e => ({ ...e, _id: String(e["_id"]) })),
      notifications: (notifications as Array<Record<string, unknown>>).map(n => ({ ...n, _id: String(n["_id"]) })),
      api_keys: (apiKeys as Array<Record<string, unknown>>).map(k => ({
        id: String(k["_id"]),
        name: k["name"],
        key_prefix: String(k["key"] ?? "").slice(0, 8) + "…[REDACTED]",
        scopes: k["scopes"],
        created_at: k["created_at"],
        last_used: k["last_used"],
      })),
      notification_preferences: notifPrefs,
    };

    await auditFromReq(req, "gdpr.data_export", "users", userId);
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Content-Disposition", `attachment; filename="my-data-export-${dateStr}.json"`);
    res.json(exportData);
  } catch (err) {
    logger.error({ err }, "GDPR export error");
    res.status(500).json({ error: "Export failed" });
  }
});

// DELETE /gdpr/my-account — cascading soft-delete: anonymise PII across all collections, keep audit trail
router.delete("/gdpr/my-account", requireAuth, async (req, res) => {
  try {
    const sess = req.session as unknown as { userId?: string };
    const userId = sess.userId;
    if (!userId) return res.status(401).json({ error: "Not authenticated" });

    const deletedAt = new Date();
    const anonEmail = `deleted_${userId}@deleted.invalid`;

    // 1. Anonymize user profile
    await col("users").updateOne(
      { _id: new ObjectId(userId) } as Record<string, unknown>,
      { $set: { email: anonEmail, name: "Deleted User", deleted_at: deletedAt, totp_secret: null, profile_image: null } }
    );

    // 2. Soft-delete scan jobs
    await col("scan_jobs").updateMany(
      { user_id: userId } as Record<string, unknown>,
      { $set: { deleted_at: deletedAt, user_id: anonEmail } }
    );

    // 3. Anonymize findings (keep for security records, anonymize owner)
    await col("findings").updateMany(
      { user_id: userId } as Record<string, unknown>,
      { $set: { user_id: anonEmail, anonymized_at: deletedAt } }
    );

    // 4. Delete webhooks (no retention needed)
    await col("webhooks").deleteMany({ user_id: userId } as Record<string, unknown>);

    // 5. Delete API keys
    await col("api_keys").deleteMany({ user_id: userId } as Record<string, unknown>);

    // 6. Delete notification preferences
    await col("notification_preferences").deleteMany({ user_id: userId } as Record<string, unknown>);

    // 7. Delete notifications
    await col("notifications").deleteMany({ user_id: userId } as Record<string, unknown>);

    // 8. Log deletion to audit_log (keep for compliance — anonymized)
    await col("audit_log").insertOne({
      action: "gdpr_account_deletion",
      actor: anonEmail,
      actor_id: userId,
      deleted_at: deletedAt,
      collections_affected: ["users", "scan_jobs", "findings", "webhooks", "api_keys", "notification_preferences", "notifications"],
      created_at: deletedAt,
    } as Record<string, unknown>);

    // 9. Destroy session
    req.session.destroy(() => {
      res.clearCookie("bbp.sid");
    });

    logger.info({ userId }, "GDPR cascading soft-delete completed");
    res.json({ ok: true, message: "Account deleted and data anonymized per GDPR Article 17" });
  } catch (err) {
    logger.error({ err }, "GDPR account deletion error");
    res.status(500).json({ error: "Account deletion failed" });
  }
});

// GET /gdpr/retention-info — returns the platform data retention policy
router.get("/gdpr/retention-info", async (_req, res) => {
  try {
    const policy = await col("platform_policy").findOne({}) as Record<string, unknown> | null;
    const retentionInfo = {
      scan_jobs_days: policy?.["retention_scan_jobs_days"] ?? 365,
      findings_days: policy?.["retention_findings_days"] ?? 730,
      audit_log_days: policy?.["retention_audit_log_days"] ?? 1825,
      notifications_days: policy?.["retention_notifications_days"] ?? 90,
      api_keys_days: policy?.["retention_api_keys_days"] ?? 365,
      policy_version: policy?.["policy_version"] ?? "1.0",
      last_updated: policy?.["policy_updated_at"] ?? null,
    };
    res.json(retentionInfo);
  } catch (err) {
    logger.error({ err }, "GDPR retention info error");
    res.status(500).json({ error: "Failed to retrieve retention policy" });
  }
});

export default router;
