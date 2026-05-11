import { Router } from "express";
import crypto from "crypto";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth, requireAdmin } from "../middlewares/rbac";

const router = Router();

function formatSettings(s: Record<string, unknown>) {
  return {
    default_export_format: s["default_export_format"] ?? "json",
    webhook_url: s["webhook_url"] ?? "",
    notifications_enabled: s["notifications_enabled"] ?? true,
    ai_analysis_enabled: s["ai_analysis_enabled"] ?? true,
    max_concurrent_scans: s["max_concurrent_scans"] ?? 5,
    api_key: s["api_key"] ?? "",
    github_login: s["github_login"] ?? "",
    ai_model: s["ai_model"] ?? process.env["OPENCODE_MODEL"] ?? "nemotron-3-super-free",
    smtp_host: s["smtp_host"] ?? "",
    smtp_port: s["smtp_port"] ?? 587,
    smtp_user: s["smtp_user"] ?? "",
    smtp_from: s["smtp_from"] ?? "noreply@bugfinder.io",
  };
}

router.get("/settings", requireAuth, async (req, res) => {
  try {
    const col_ = col("settings");
    let s = (await col_.find().toArray())[0] as Record<string, unknown> | undefined;
    if (!s) {
      await col_.insertOne({
        default_export_format: "json",
        notifications_enabled: true,
        ai_analysis_enabled: true,
        max_concurrent_scans: 5,
        webhook_url: "",
        api_key: `bbp_${crypto.randomBytes(16).toString("hex")}`,
        ai_model: process.env["OPENCODE_MODEL"] ?? "nemotron-3-super-free",
        created_at: new Date(),
        updated_at: new Date(),
      });
      s = (await col_.find().toArray())[0] as Record<string, unknown>;
    }
    res.json(formatSettings(s));
  } catch (err) {
    logger.error({ err }, "Get settings error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.put("/settings", requireAdmin, async (req, res) => {
  try {
    const body = req.body as Record<string, unknown>;
    const allowed = ["default_export_format", "webhook_url", "notifications_enabled",
      "ai_analysis_enabled", "max_concurrent_scans", "ai_model",
      "smtp_host", "smtp_port", "smtp_user", "smtp_from"];

    const updates: Record<string, unknown> = { updated_at: new Date() };
    for (const key of allowed) {
      if (body[key] !== undefined) updates[key] = body[key];
    }
    // Update runtime env for AI model if changed
    if (updates["ai_model"]) process.env["OPENCODE_MODEL"] = String(updates["ai_model"]);

    const col_ = col("settings");
    const existing = await col_.find().toArray() as Array<Record<string, unknown>>;
    if (existing.length === 0) {
      await col_.insertOne({ ...updates, created_at: new Date() });
    } else {
      await col_.updateOne({ _id: existing[0]!["_id"] } as Record<string, unknown>, { $set: updates });
    }

    const updated = (await col_.find().toArray())[0] as Record<string, unknown>;
    res.json(formatSettings(updated));
  } catch (err) {
    logger.error({ err }, "Update settings error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/settings/regenerate-api-key", requireAdmin, async (req, res) => {
  try {
    const newKey = `bbp_${crypto.randomBytes(16).toString("hex")}`;
    const col_ = col("settings");
    const existing = await col_.find().toArray() as Array<Record<string, unknown>>;
    if (existing.length === 0) {
      await col_.insertOne({ api_key: newKey, created_at: new Date(), updated_at: new Date() });
    } else {
      await col_.updateOne({ _id: existing[0]!["_id"] } as Record<string, unknown>, { $set: { api_key: newKey, updated_at: new Date() } });
    }
    res.json({ api_key: newKey });
  } catch (err) {
    logger.error({ err }, "Regenerate API key error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
