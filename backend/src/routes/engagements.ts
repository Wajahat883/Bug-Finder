import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";

const router = Router();

function formatEngagement(e: Record<string, unknown>) {
  return {
    id: String(e["_id"]),
    name: e["name"],
    description: e["description"] ?? null,
    status: e["status"] ?? "active",
    start_date: e["start_date"] ?? null,
    end_date: e["end_date"] ?? null,
    scope_targets: (e["scope_targets"] as string[]) ?? [],
    team_members: (e["team_members"] as unknown[]) ?? [],
    rules_of_engagement: e["rules_of_engagement"] ?? null,
    created_by: e["created_by"] ?? null,
    created_at: e["created_at"],
    updated_at: e["updated_at"] ?? null,
  };
}

// GET /engagements — list all
router.get("/engagements", requireAuth, async (_req, res) => {
  try {
    const engagements = (await col("engagements").find({}).sort({ created_at: -1 }).toArray()) as Array<Record<string, unknown>>;
    res.json(engagements.map(formatEngagement));
  } catch (err) {
    logger.error({ err }, "List engagements error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /engagements — create
router.post("/engagements", requireAuth, async (req, res) => {
  try {
    const session = (req as unknown as { session: Record<string, unknown> }).session;
    const body = req.body as Record<string, unknown>;
    if (!body["name"]) return res.status(400).json({ error: "name is required" });
    const now = new Date();
    const insert = await col("engagements").insertOne({
      name: body["name"],
      description: body["description"] ?? null,
      status: body["status"] ?? "active",
      start_date: body["start_date"] ? new Date(body["start_date"] as string) : null,
      end_date: body["end_date"] ? new Date(body["end_date"] as string) : null,
      scope_targets: [],
      team_members: body["team_members"] ?? [],
      rules_of_engagement: body["rules_of_engagement"] ?? null,
      created_by: (session["username"] as string) ?? (session["userId"] as string) ?? "unknown",
      created_at: now,
      updated_at: now,
    });
    const saved = (await col("engagements").findOne({ _id: insert.insertedId } as Record<string, unknown>)) as Record<string, unknown>;
    res.status(201).json(formatEngagement(saved));
  } catch (err) {
    logger.error({ err }, "Create engagement error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /engagements/:id — get with targets and scan count
router.get("/engagements/:id", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    const engagement = (await col("engagements").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!engagement) return res.status(404).json({ error: "Engagement not found" });
    const formatted = formatEngagement(engagement);
    // Enrich with scan count
    const targetIds = formatted.scope_targets;
    const scanCount = await col("scan_jobs").countDocuments({ target_url: { $in: await getTargetUrls(targetIds) } } as Record<string, unknown>);
    res.json({ ...formatted, scan_count: scanCount });
  } catch (err) {
    logger.error({ err }, "Get engagement error");
    res.status(500).json({ error: "Internal server error" });
  }
});

async function getTargetUrls(targetIds: string[]): Promise<string[]> {
  if (targetIds.length === 0) return [];
  const validIds = targetIds.filter(id => ObjectId.isValid(id)).map(id => new ObjectId(id));
  const targets = await col("targets").find({ _id: { $in: validIds } } as Record<string, unknown>).toArray() as Array<Record<string, unknown>>;
  return targets.map(t => String(t["url"] ?? "")).filter(Boolean);
}

// PATCH /engagements/:id — update
router.patch("/engagements/:id", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    const body = req.body as Record<string, unknown>;
    const updates: Record<string, unknown> = { updated_at: new Date() };
    for (const key of ["name", "description", "status", "rules_of_engagement", "team_members"]) {
      if (body[key] !== undefined) updates[key] = body[key];
    }
    if (body["start_date"]) updates["start_date"] = new Date(body["start_date"] as string);
    if (body["end_date"]) updates["end_date"] = new Date(body["end_date"] as string);
    await col("engagements").updateOne({ _id: new ObjectId(id) } as Record<string, unknown>, { $set: updates });
    const updated = (await col("engagements").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown>;
    res.json(formatEngagement(updated));
  } catch (err) {
    logger.error({ err }, "Update engagement error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// DELETE /engagements/:id
router.delete("/engagements/:id", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    await col("engagements").deleteOne({ _id: new ObjectId(id) } as Record<string, unknown>);
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "Delete engagement error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /engagements/:id/targets — add target to scope
router.post("/engagements/:id/targets", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    const { target_id } = req.body as { target_id?: string };
    if (!target_id) return res.status(400).json({ error: "target_id is required" });
    await col("engagements").updateOne(
      { _id: new ObjectId(id) } as Record<string, unknown>,
      { $addToSet: { scope_targets: target_id }, $set: { updated_at: new Date() } } as Record<string, unknown>
    );
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "Add target to engagement error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// DELETE /engagements/:id/targets/:targetId — remove from scope
router.delete("/engagements/:id/targets/:targetId", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]); const targetId = String(req.params["targetId"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    await col("engagements").updateOne(
      { _id: new ObjectId(id) } as Record<string, unknown>,
      { $pull: { scope_targets: targetId }, $set: { updated_at: new Date() } } as Record<string, unknown>
    );
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "Remove target from engagement error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /engagements/:id/findings — all findings from in-scope targets
router.get("/engagements/:id/findings", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    const engagement = (await col("engagements").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!engagement) return res.status(404).json({ error: "Engagement not found" });
    const targetUrls = await getTargetUrls((engagement["scope_targets"] as string[]) ?? []);
    const findings = (await col("findings").find({ target_url: { $in: targetUrls } } as Record<string, unknown>).sort({ created_at: -1 }).toArray()) as Array<Record<string, unknown>>;
    res.json(findings.map((f) => ({
      id: String(f["_id"]),
      title: f["title"],
      severity: f["severity"],
      category: f["category"],
      endpoint: f["endpoint"],
      validation_status: f["validation_status"],
      cvss_score: f["cvss_score"],
      created_at: f["created_at"],
    })));
  } catch (err) {
    logger.error({ err }, "Engagement findings error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /engagements/:id/summary — total scans, findings by severity, risk scores
router.get("/engagements/:id/summary", requireAuth, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });
    const engagement = (await col("engagements").findOne({ _id: new ObjectId(id) } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!engagement) return res.status(404).json({ error: "Engagement not found" });
    const targetUrls = await getTargetUrls((engagement["scope_targets"] as string[]) ?? []);
    const [findings, scans] = await Promise.all([
      col("findings").find({ target_url: { $in: targetUrls } } as Record<string, unknown>).toArray() as Promise<Array<Record<string, unknown>>>,
      col("scan_jobs").find({ target_url: { $in: targetUrls } } as Record<string, unknown>).toArray() as Promise<Array<Record<string, unknown>>>,
    ]);
    const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      const sev = String(f["severity"] ?? "info") as keyof typeof sevCounts;
      if (sev in sevCounts) sevCounts[sev]++;
    }
    const avgRisk = scans.length > 0 ? Math.round(scans.reduce((a, s) => a + Number(s["risk_score"] ?? 0), 0) / scans.length) : 0;
    res.json({
      total_scans: scans.length,
      total_findings: findings.length,
      findings_by_severity: sevCounts,
      average_risk_score: avgRisk,
      target_count: targetUrls.length,
    });
  } catch (err) {
    logger.error({ err }, "Engagement summary error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
