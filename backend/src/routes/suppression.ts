/**
 * Finding Suppression Rules
 *
 * Enterprise scanners maintain persistent suppression rules so accepted-risk
 * findings don't regenerate noise on every scan. Rules are keyed by
 * (dedup_key, target_url) and checked during saveFinding() before insertion.
 *
 * POST   /suppression-rules           — Create rule (accepted-risk)
 * GET    /suppression-rules           — List all active rules
 * DELETE /suppression-rules/:id       — Remove rule (risk no longer accepted)
 * POST   /suppression-rules/from-finding/:findingId — Create rule from existing finding
 */

import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";
import { auditFromReq } from "../lib/audit";

const router = Router();
router.use(requireAuth);

function formatRule(r: Record<string, unknown>) {
  return {
    id: String(r["_id"]),
    target_url: r["target_url"],
    dedup_key: r["dedup_key"],
    title: r["title"],
    endpoint: r["endpoint"],
    category: r["category"],
    reason: r["reason"],
    expires_at: r["expires_at"] ?? null,
    created_by: r["created_by"],
    created_at: r["created_at"],
  };
}

// Create a suppression rule manually
router.post("/suppression-rules", async (req, res) => {
  try {
    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const body = req.body as {
      target_url?: string;
      dedup_key?: string;
      title?: string;
      endpoint?: string;
      category?: string;
      reason?: string;
      expires_at?: string;
    };

    if (!body.target_url || !body.dedup_key) {
      return res.status(400).json({ error: "target_url and dedup_key are required" });
    }

    // Check for duplicates
    const existing = await col("suppression_rules").findOne({
      target_url: body.target_url,
      dedup_key: body.dedup_key,
    } as Record<string, unknown>);
    if (existing) {
      return res.status(409).json({ error: "Suppression rule already exists for this finding" });
    }

    const now = new Date();
    const expiresAt = body.expires_at ? new Date(body.expires_at) : null;

    const ins = await col("suppression_rules").insertOne({
      target_url: body.target_url,
      dedup_key: body.dedup_key,
      title: body.title ?? "",
      endpoint: body.endpoint ?? "",
      category: body.category ?? "",
      reason: body.reason ?? "Accepted risk",
      expires_at: expiresAt,
      created_by: session.userId,
      created_at: now,
      updated_at: now,
    });

    await auditFromReq(req, "suppression_rule.create", "suppression_rules", String(ins.insertedId), {
      target_url: body.target_url, dedup_key: body.dedup_key, reason: body.reason,
    });

    const saved = await col("suppression_rules").findOne({ _id: ins.insertedId } as Record<string, unknown>) as Record<string, unknown>;
    res.status(201).json(formatRule(saved));
  } catch (err) {
    logger.error({ err }, "Create suppression rule error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// Create rule directly from an existing finding — convenience endpoint used by UI
router.post("/suppression-rules/from-finding/:findingId", async (req, res) => {
  try {
    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const { findingId } = req.params;
    if (!ObjectId.isValid(findingId)) return res.status(404).json({ error: "Finding not found" });

    const finding = await col("findings").findOne({ _id: new ObjectId(findingId) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!finding) return res.status(404).json({ error: "Finding not found" });

    // Ownership check
    if (session.role !== "admin" && finding["user_id"] !== session.userId) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const { reason, expires_at } = req.body as { reason?: string; expires_at?: string };
    const dedupKey = String(finding["dedup_key"] ?? `${finding["title"]}||${finding["endpoint"]}`);
    const targetUrl = String(finding["target_url"] ?? "");

    const existing = await col("suppression_rules").findOne({
      target_url: targetUrl, dedup_key: dedupKey,
    } as Record<string, unknown>);
    if (existing) {
      return res.status(409).json({ error: "Suppression rule already exists for this finding" });
    }

    const now = new Date();
    const ins = await col("suppression_rules").insertOne({
      target_url: targetUrl,
      dedup_key: dedupKey,
      title: String(finding["title"] ?? ""),
      endpoint: String(finding["endpoint"] ?? ""),
      category: String(finding["category"] ?? ""),
      reason: reason ?? "Accepted risk — suppressed from finding",
      expires_at: expires_at ? new Date(expires_at) : null,
      finding_id: new ObjectId(findingId),
      created_by: session.userId,
      created_at: now,
      updated_at: now,
    });

    // Mark the finding itself as suppressed
    await col("findings").updateOne(
      { _id: new ObjectId(findingId) } as Record<string, unknown>,
      { $set: { validation_status: "suppressed", suppressed_at: now, suppressed_by: session.userId, suppression_reason: reason ?? "Accepted risk" } }
    );

    await auditFromReq(req, "suppression_rule.create_from_finding", "suppression_rules", String(ins.insertedId), {
      finding_id: findingId, dedup_key: dedupKey,
    });

    const saved = await col("suppression_rules").findOne({ _id: ins.insertedId } as Record<string, unknown>) as Record<string, unknown>;
    res.status(201).json(formatRule(saved));
  } catch (err) {
    logger.error({ err }, "Create suppression from finding error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// List suppression rules
router.get("/suppression-rules", async (req, res) => {
  try {
    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const target = req.query["target_url"] as string | undefined;
    const query: Record<string, unknown> = {};
    if (session.role !== "admin") query["created_by"] = session.userId;
    if (target) query["target_url"] = target;

    const rules = await col("suppression_rules")
      .find(query)
      .sort({ created_at: -1 })
      .toArray() as Array<Record<string, unknown>>;

    // Filter out expired rules on read (lazy expiry)
    const now = new Date();
    const active = rules.filter(r => !r["expires_at"] || new Date(r["expires_at"] as string) > now);

    res.json({ items: active.map(formatRule), total: active.length });
  } catch (err) {
    logger.error({ err }, "List suppression rules error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// Delete a suppression rule
router.delete("/suppression-rules/:id", async (req, res) => {
  try {
    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const rule = await col("suppression_rules").findOne({ _id: new ObjectId(id) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!rule) return res.status(404).json({ error: "Not found" });

    if (session.role !== "admin" && rule["created_by"] !== session.userId) {
      return res.status(403).json({ error: "Forbidden" });
    }

    await col("suppression_rules").deleteOne({ _id: new ObjectId(id) } as Record<string, unknown>);
    await auditFromReq(req, "suppression_rule.delete", "suppression_rules", id, {
      dedup_key: rule["dedup_key"],
    });

    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "Delete suppression rule error");
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * Check if a finding should be suppressed.
 * Called from saveFinding() in scanner/index.ts before inserting a finding.
 */
export async function isSuppressionActive(dedupKey: string, targetUrl: string): Promise<boolean> {
  try {
    const now = new Date();
    const rule = await col("suppression_rules").findOne({
      dedup_key: dedupKey,
      target_url: targetUrl,
      $or: [
        { expires_at: null },
        { expires_at: { $gt: now } },
      ],
    } as Record<string, unknown>);
    return rule !== null;
  } catch {
    return false; // fail open — don't suppress if DB unavailable
  }
}

export default router;
