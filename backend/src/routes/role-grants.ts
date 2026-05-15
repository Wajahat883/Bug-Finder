import { Router } from "express";
import { z } from "zod";
import { col, ObjectId } from "../lib/db";
import { requireAdmin } from "../middlewares/rbac";
import { auditFromReq } from "../lib/audit";

const router = Router();

const createGrantSchema = z.object({
  user_id: z.string().min(1),
  role: z.enum(["admin", "senior", "analyst", "viewer"]),
  expires_in_days: z.number().min(1).max(90).default(7),
  reason: z.string().max(500).optional(),
});

// GET /role-grants — list all active grants (admin only)
router.get("/role-grants", requireAdmin, async (_req, res) => {
  try {
    const grants = await col("role_grants").find({ active: true, expires_at: { $gt: new Date() } } as Record<string, unknown>).sort({ created_at: -1 }).toArray();
    res.json(grants.map(g => ({ ...g, id: String(g["_id"]) })));
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /role-grants — create a time-boxed role grant (admin only)
router.post("/role-grants", requireAdmin, async (req, res) => {
  const parsed = createGrantSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.errors[0]?.message ?? "Validation failed" });
  const { user_id, role, expires_in_days, reason } = parsed.data;
  try {
    const expiresAt = new Date(Date.now() + expires_in_days * 86400000);
    const insert = await col("role_grants").insertOne({
      user_id, role, expires_at: expiresAt, active: true,
      reason: reason ?? null, created_at: new Date(),
    });
    await auditFromReq(req, "role_grant.create", "users", user_id, { role, expires_in_days });
    res.status(201).json({ id: String(insert.insertedId), user_id, role, expires_at: expiresAt });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

// DELETE /role-grants/:id — revoke a grant (admin only)
router.delete("/role-grants/:id", requireAdmin, async (req, res) => {
  try {
    await col("role_grants").updateOne(
      { _id: new ObjectId(req.params.id) } as Record<string, unknown>,
      { $set: { active: false, revoked_at: new Date() } }
    );
    await auditFromReq(req, "role_grant.revoke", "role_grants", req.params.id);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
