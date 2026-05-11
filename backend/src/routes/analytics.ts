import { Router } from "express";
import { col } from "../lib/db";

const router = Router();

router.get("/analytics", async (_req, res) => {
  try {
    const [totalScans, totalFindings, totalTargets] = await Promise.all([
      col("scan_jobs").countDocuments(),
      col("findings").countDocuments(),
      col("targets").countDocuments(),
    ]);

    const findings = await col("findings").find({}).toArray();
    const bySeverity = findings.reduce<Record<string, number>>((acc, f) => {
      const sev = String((f as Record<string, unknown>).severity ?? "unknown");
      acc[sev] = (acc[sev] ?? 0) + 1;
      return acc;
    }, {});

    res.json({ totalScans, totalFindings, totalTargets, bySeverity });
  } catch {
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
