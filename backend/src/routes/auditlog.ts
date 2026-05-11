import { Router } from "express";
import { col } from "../lib/db";
import { requireAdmin } from "../middlewares/rbac";

const router = Router();

router.get("/audit-log", requireAdmin, async (req, res) => {
  try {
    const logs = await col("audit_log").find({}).sort({ created_at: -1 }).toArray();
    res.json(logs);
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
