import { Router } from "express";
import { col } from "../lib/db";
import { logger } from "../lib/logger";

const router = Router();

router.get("/settings", async (req, res) => {
  try {
    const settingsCol = col("settings");
    let settings = (await settingsCol.find().toArray()) as Array<Record<string, unknown>>;
    let setting = settings[0];

    if (!setting) {
      await settingsCol.insertOne({
        default_export_format: "json",
        notifications_enabled: true,
        ai_analysis_enabled: true,
        max_concurrent_scans: 5,
        webhook_url: "",
        api_key: `bbp_${Math.random().toString(36).substring(2, 18)}`,
        github_login: "Wajahat883",
        created_at: new Date(),
        updated_at: new Date(),
      });
      const freshSettings = (await settingsCol.find().toArray()) as Array<Record<string, unknown>>;
      setting = freshSettings[0]!;
    }

    res.json({
      default_export_format: setting["default_export_format"] ?? "json",
      webhook_url: setting["webhook_url"] ?? "",
      notifications_enabled: setting["notifications_enabled"] ?? true,
      ai_analysis_enabled: setting["ai_analysis_enabled"] ?? true,
      max_concurrent_scans: setting["max_concurrent_scans"] ?? 5,
      api_key: setting["api_key"] ?? "",
      github_login: setting["github_login"] ?? "Wajahat883",
    });
  } catch (err) {
    logger.error({ err }, "Get settings error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.put("/settings", async (req, res) => {
  try {
    const body = req.body as {
      default_export_format?: string;
      webhook_url?: string;
      notifications_enabled?: boolean;
      ai_analysis_enabled?: boolean;
      max_concurrent_scans?: number;
    };

    const updates: Record<string, unknown> = { updated_at: new Date() };
    if (body.default_export_format !== undefined) updates["default_export_format"] = body.default_export_format;
    if (body.webhook_url !== undefined) updates["webhook_url"] = body.webhook_url;
    if (body.notifications_enabled !== undefined) updates["notifications_enabled"] = body.notifications_enabled;
    if (body.ai_analysis_enabled !== undefined) updates["ai_analysis_enabled"] = body.ai_analysis_enabled;
    if (body.max_concurrent_scans !== undefined) updates["max_concurrent_scans"] = body.max_concurrent_scans;

    const settingsCol = col("settings");
    const existing = (await settingsCol.find().toArray()) as Array<Record<string, unknown>>;
    if (existing.length === 0) {
      await settingsCol.insertOne({ ...updates, created_at: new Date() });
    } else {
      await settingsCol.updateOne({ _id: existing[0]!["_id"] } as Record<string, unknown>, { $set: updates });
    }

    const updated = (await settingsCol.find().toArray()) as Array<Record<string, unknown>>;
    const s = updated[0]!;
    res.json({
      default_export_format: s["default_export_format"] ?? "json",
      webhook_url: s["webhook_url"] ?? "",
      notifications_enabled: s["notifications_enabled"] ?? true,
      ai_analysis_enabled: s["ai_analysis_enabled"] ?? true,
      max_concurrent_scans: s["max_concurrent_scans"] ?? 5,
      api_key: s["api_key"] ?? "",
      github_login: s["github_login"] ?? "Wajahat883",
    });
  } catch (err) {
    logger.error({ err }, "Update settings error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
