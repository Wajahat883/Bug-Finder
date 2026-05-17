import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";

const router = Router();

function formatRemediation(r: Record<string, unknown>) {
  return {
    id: String(r["_id"]),
    finding_id: r["finding_id"] ? String(r["finding_id"]) : null,
    scan_job_id: r["scan_job_id"] ? String(r["scan_job_id"]) : null,
    title: r["title"],
    description: r["description"],
    patch_snippet: r["patch_snippet"] ?? null,
    status: r["status"],
    created_at: r["created_at"],
    updated_at: r["updated_at"],
  };
}

router.get("/remediations", async (req, res) => {
  try {
    const all = (await col("remediations").find({}).sort({ created_at: -1 }).toArray()) as Array<Record<string, unknown>>;
    res.json(all.map(formatRemediation));
  } catch (err) {
    logger.error({ err }, "List remediations error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/remediations", async (req, res) => {
  try {
    const body = req.body as {
      finding_id: string;
      scan_job_id: string;
      title: string;
      description: string;
      patch_snippet?: string;
    };

    if (!body.finding_id || !body.scan_job_id || !body.title || !body.description) {
      return res.status(400).json({ error: "finding_id, scan_job_id, title, and description are required" });
    }

    const now = new Date();
    const insert = await col("remediations").insertOne({
      finding_id: ObjectId.isValid(body.finding_id) ? new ObjectId(body.finding_id) : body.finding_id,
      scan_job_id: ObjectId.isValid(body.scan_job_id) ? new ObjectId(body.scan_job_id) : body.scan_job_id,
      title: body.title,
      description: body.description,
      patch_snippet: body.patch_snippet ?? null,
      status: "pending",
      created_at: now,
      updated_at: now,
    });

    const created = (await col("remediations").findOne({ _id: insert.insertedId } as Record<string, unknown>)) as Record<string, unknown>;
    res.status(201).json(formatRemediation(created));
  } catch (err) {
    logger.error({ err }, "Create remediation error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/remediations/:id", async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const rem = (await col("remediations").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!rem) return res.status(404).json({ error: "Remediation not found" });

    res.json(formatRemediation(rem));
  } catch (err) {
    logger.error({ err }, "Get remediation error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.patch("/remediations/:id", async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const body = req.body as { status?: string };
    if (body.status) {
      await col("remediations").updateOne(
        { _id: new ObjectId(id) } as Record<string, unknown>,
        { $set: { status: body.status, updated_at: new Date() } }
      );
    }

    const updated = (await col("remediations").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown>;
    res.json(formatRemediation(updated));
  } catch (err) {
    logger.error({ err }, "Update remediation error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// Evidence for remediations
router.get("/remediations/:id/evidence", requireAuth, async (req, res) => {
  try {
    const evidence = await col("remediation_evidence").find({ remediation_id: req.params.id } as Record<string, unknown>).toArray() as Array<Record<string, unknown>>;
    res.json(evidence.map(e => ({ id: String(e["_id"]), filename: e["filename"], content_type: e["content_type"], label: e["label"], size_bytes: e["size_bytes"], created_at: e["created_at"], base64_data: e["base64_data"] })));
  } catch { res.status(500).json({ error: "Internal server error" }); }
});

router.post("/remediations/:id/evidence", requireAuth, async (req, res) => {
  try {
    const { filename, content_type, base64_data, label } = req.body as Record<string, string>;
    await col("remediation_evidence").insertOne({ remediation_id: req.params.id, filename, content_type, base64_data, label, size_bytes: Math.ceil(base64_data.length * 0.75), created_at: new Date() } as Record<string, unknown>);
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Internal server error" }); }
});

router.delete("/remediations/:id/evidence/:evidenceId", requireAuth, async (req, res) => {
  try {
    const evidenceId = String(req.params["evidenceId"]);
    if (!ObjectId.isValid(evidenceId)) return res.status(404).json({ error: "Not found" });
    await col("remediation_evidence").deleteOne({ _id: new ObjectId(evidenceId) } as Record<string, unknown>);
    res.json({ ok: true });
  } catch { res.status(500).json({ error: "Internal server error" }); }
});

// Activity log for remediations
router.get("/remediations/:id/activity", requireAuth, async (req, res) => {
  try {
    const activities = await col("audit_log").find({ resource: "remediation", resource_id: req.params.id } as Record<string, unknown>).sort({ created_at: -1 }).limit(50).toArray() as Array<Record<string, unknown>>;
    res.json(activities.map(a => ({ action: a["action"], actor: a["username"] ?? a["userId"], timestamp: a["created_at"], details: a["details"] })));
  } catch { res.status(500).json({ error: "Internal server error" }); }
});

export default router;
