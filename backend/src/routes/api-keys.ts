import { Router } from "express";
import { ObjectId } from "mongodb";
import crypto from "crypto";
import { z } from "zod";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth, requireAdmin } from "../middlewares/rbac";
import { sendEmail } from "../services/email";

const VALID_SCOPES = ["read", "write", "scan", "admin"] as const;
const createKeySchema = z.object({
  name: z.string().min(1, "name is required").max(100),
  scopes: z.array(z.enum(VALID_SCOPES)).optional(),
  expires_days: z.number().int().min(1).max(365).optional(),
});
const patchKeySchema = z.object({
  name: z.string().max(100).optional(),
  active: z.boolean().optional(),
});

const router = Router();

function generateKey(): string {
  return "bfp_" + crypto.randomBytes(24).toString("hex");
}

// GET /api-keys — List all API keys
router.get("/api-keys", requireAdmin, async (_req, res) => {
  try {
    const keys = await col("api_keys").find({}).sort({ created_at: -1 }).toArray() as Array<Record<string, unknown>>;
    res.json(keys.map((k) => ({
      id: String(k["_id"]),
      name: k["name"],
      key_preview: String(k["key"] ?? "").slice(0, 8) + "..." + String(k["key"] ?? "").slice(-4),
      scopes: k["scopes"] ?? ["read"],
      active: k["active"] ?? true,
      last_used: k["last_used"] ?? null,
      usage_count: k["usage_count"] ?? 0,
      created_at: k["created_at"],
      expires_at: k["expires_at"] ?? null,
      rotated_at: k["rotated_at"] ?? null,
    })));
  } catch (err) {
    logger.error({ err }, "List API keys error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /api-keys — Create new API key
router.post("/api-keys", requireAdmin, async (req, res) => {
  try {
    const parsed = createKeySchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.errors[0]?.message ?? "Validation failed" });
    const { name, scopes, expires_days } = parsed.data;
    const key = generateKey();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + (expires_days ?? 90));
    const insert = await col("api_keys").insertOne({
      name: name.trim(),
      key,
      scopes: scopes ?? ["read"],
      active: true,
      usage_count: 0,
      last_used: null,
      expires_at: expiresAt,
      created_at: new Date(),
      updated_at: new Date(),
    });
    res.status(201).json({
      id: String(insert.insertedId),
      name,
      key,
      scopes: scopes ?? ["read"],
      active: true,
      expires_at: expiresAt,
      message: "Store this key securely — it won't be shown again",
    });
  } catch (err) {
    logger.error({ err }, "Create API key error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// PATCH /api-keys/:id — Toggle active/update name
router.patch("/api-keys/:id", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    const parsed = patchKeySchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.errors[0]?.message ?? "Validation failed" });
    const { name, active } = parsed.data;
    const update: Record<string, unknown> = { updated_at: new Date() };
    if (name !== undefined) update["name"] = name.trim();
    if (active !== undefined) update["active"] = active;
    await col("api_keys").updateOne({ _id: new ObjectId(id) } as Record<string, unknown>, { $set: update });
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "Update API key error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// DELETE /api-keys/:id — Revoke API key
router.delete("/api-keys/:id", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    await col("api_keys").deleteOne({ _id: new ObjectId(id) } as Record<string, unknown>);
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "Delete API key error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /api-keys/:id/rotate — Generate new secret, mark old one expired, return new key
router.post("/api-keys/:id/rotate", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const newKey = generateKey(); // bfp_<48 hex chars>
    const newExpiresAt = new Date();
    newExpiresAt.setDate(newExpiresAt.getDate() + 90);

    const result = await col("api_keys").updateOne(
      { _id: new ObjectId(id) } as Record<string, unknown>,
      {
        $set: {
          key: newKey,
          expires_at: newExpiresAt,
          rotated_at: new Date(),
          updated_at: new Date(),
          // Store a preview of the old key prefix for audit trail
          last_key_prefix: newKey.slice(0, 12) + "...",
        },
      } as Record<string, unknown>
    );

    if (result.matchedCount === 0) return res.status(404).json({ error: "Not found" });

    logger.info({ id }, "API key rotated");
    res.json({ ok: true, new_key: newKey, expires_at: newExpiresAt });
  } catch (err) {
    logger.error({ err }, "Rotate API key error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /admin/api-keys/send-rotation-reminders — notify users with keys expiring in 14 days (admin only)
router.post("/admin/api-keys/send-rotation-reminders", requireAdmin, async (req, res) => {
  try {
    const now = new Date();
    const in14Days = new Date(now.getTime() + 14 * 24 * 60 * 60 * 1000);

    const expiringKeys = (await col("api_keys")
      .find({
        active: true,
        expires_at: { $gte: now, $lte: in14Days },
      } as Record<string, unknown>)
      .toArray()) as Array<Record<string, unknown>>;

    let notified = 0;
    for (const apiKey of expiringKeys) {
      const userId = String(apiKey["user_id"] ?? "");
      if (!userId) continue;

      const user = (await col("users").findOne(
        { _id: new ObjectId(userId) } as Record<string, unknown>
      )) as Record<string, unknown> | null;

      const email = String(user?.["email"] ?? "");
      if (!email) continue;

      const expiresAt = apiKey["expires_at"] as Date;
      const keyName = String(apiKey["name"] ?? "API Key");
      const daysLeft = Math.ceil((expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

      const sent = await sendEmail({
        to: email,
        subject: `Action required: Your Bug Finder Pro API key "${keyName}" expires in ${daysLeft} day(s)`,
        html: `<p>Your API key <strong>${keyName}</strong> will expire on <strong>${expiresAt.toDateString()}</strong>.</p>
               <p>Please rotate your key before it expires to avoid service interruption.</p>
               <p>You can rotate your key from the API Keys section in your account settings.</p>`,
        text: `Your API key "${keyName}" expires on ${expiresAt.toDateString()} (${daysLeft} day(s) remaining). Please rotate it to avoid service interruption.`,
      });

      if (sent) {
        notified++;
        await col("audit_log").insertOne({
          action: "api_key.rotation_reminder_sent",
          actor: "system",
          target_id: String(apiKey["_id"]),
          target_type: "api_key",
          metadata: { key_name: keyName, expires_at: expiresAt, days_left: daysLeft, user_email: email },
          created_at: new Date(),
        });
      }
    }

    logger.info({ total: expiringKeys.length, notified }, "API key rotation reminders sent");
    res.json({ ok: true, expiring_keys: expiringKeys.length, reminders_sent: notified });
  } catch (err) {
    logger.error({ err }, "Send rotation reminders error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
