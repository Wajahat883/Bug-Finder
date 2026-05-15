import { Router } from "express";
import { ObjectId } from "mongodb";
import crypto from "crypto";
import { z } from "zod";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAdmin } from "../middlewares/rbac";

const VALID_SCOPES = ["read", "write", "scan", "admin"] as const;
const createKeySchema = z.object({
  name: z.string().min(1, "name is required").max(100),
  scopes: z.array(z.enum(VALID_SCOPES)).optional(),
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
    const { name, scopes } = parsed.data;
    const key = generateKey();
    const insert = await col("api_keys").insertOne({
      name: name.trim(),
      key,
      scopes: scopes ?? ["read"],
      active: true,
      usage_count: 0,
      last_used: null,
      created_at: new Date(),
      updated_at: new Date(),
    });
    res.status(201).json({
      id: String(insert.insertedId),
      name,
      key,
      scopes: scopes ?? ["read"],
      active: true,
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

export default router;
