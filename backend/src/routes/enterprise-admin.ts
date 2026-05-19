/**
 * Enterprise admin endpoints: anomaly alerts, IP allowlist, active sessions,
 * AI token usage dashboard, forced 2FA policy, data retention, audit export.
 */
import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { requireAuth, requireAdmin } from "../middlewares/rbac";
import { errorResponse } from "../lib/response";
import { logger } from "../lib/logger";

const router = Router();

// ── Anomaly Alerts ────────────────────────────────────────────────────────────

router.get("/admin/anomaly-alerts", requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(String(req.query["limit"] ?? "50")), 200);
    const unackOnly = req.query["unack"] === "true";
    const query: Record<string, unknown> = unackOnly ? { acknowledged: false } : {};
    const alerts = await col("anomaly_alerts").find(query).sort({ created_at: -1 }).limit(limit).toArray();
    res.json(alerts.map(a => ({
      id: String(a["_id"]),
      type: a["type"],
      user_id: a["user_id"],
      details: a["details"],
      acknowledged: a["acknowledged"] ?? false,
      created_at: a["created_at"],
    })));
  } catch (err) {
    logger.error({ err }, "List anomaly alerts error");
    errorResponse(res, 500, "Internal Server Error");
  }
});

router.post("/admin/anomaly-alerts/:id/acknowledge", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return errorResponse(res, 404, "Not Found");
    await col("anomaly_alerts").updateOne(
      { _id: new ObjectId(id) } as Record<string, unknown>,
      { $set: { acknowledged: true, acknowledged_at: new Date() } }
    );
    res.json({ ok: true });
  } catch (err) {
    errorResponse(res, 500, "Internal Server Error");
  }
});

router.post("/admin/anomaly-alerts/acknowledge-all", requireAdmin, async (_req, res) => {
  try {
    await col("anomaly_alerts").updateMany({ acknowledged: false }, { $set: { acknowledged: true, acknowledged_at: new Date() } });
    res.json({ ok: true });
  } catch (err) {
    errorResponse(res, 500, "Internal Server Error");
  }
});

// ── IP Allowlist ──────────────────────────────────────────────────────────────

router.get("/admin/ip-allowlist", requireAdmin, async (_req, res) => {
  try {
    const list = await col("ip_allowlist").find({}).sort({ created_at: -1 }).toArray();
    res.json(list.map(e => ({ id: String(e["_id"]), cidr: e["cidr"], label: e["label"], created_at: e["created_at"] })));
  } catch (err) {
    errorResponse(res, 500, "Internal Server Error");
  }
});

router.post("/admin/ip-allowlist", requireAdmin, async (req, res) => {
  try {
    const { cidr, label } = req.body as { cidr?: string; label?: string };
    if (!cidr) return errorResponse(res, 422, "Validation Failed", "cidr is required");
    const cidrPattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$|^([0-9a-fA-F:]+)(\/\d{1,3})?$/;
    if (!cidrPattern.test(cidr)) return errorResponse(res, 422, "Validation Failed", "Invalid CIDR notation");
    const id = new ObjectId();
    await col("ip_allowlist").insertOne({ _id: id, cidr, label: label ?? "", created_at: new Date() });
    res.status(201).json({ id: String(id), cidr, label, created_at: new Date() });
  } catch (err) {
    errorResponse(res, 500, "Internal Server Error");
  }
});

router.delete("/admin/ip-allowlist/:id", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return errorResponse(res, 404, "Not Found");
    await col("ip_allowlist").deleteOne({ _id: new ObjectId(id) } as Record<string, unknown>);
    res.json({ ok: true });
  } catch (err) {
    errorResponse(res, 500, "Internal Server Error");
  }
});

// ── Active Sessions ───────────────────────────────────────────────────────────

router.get("/admin/sessions", requireAdmin, async (_req, res) => {
  try {
    // Sessions are stored in MongoDB session store (connect-mongo)
    const sessions = await col("sessions").find({}).sort({ "session.cookie.expires": -1 }).limit(100).toArray();
    res.json(sessions.map(s => {
      const sess = (s["session"] as Record<string, unknown> | undefined) ?? {};
      return {
        id: String(s["_id"]),
        user_id: sess["userId"] ?? null,
        username: sess["username"] ?? null,
        role: sess["role"] ?? null,
        expires: (sess["cookie"] as Record<string, unknown> | undefined)?.["expires"] ?? null,
        created_at: s["_id"] ? new ObjectId(String(s["_id"])).getTimestamp() : null,
      };
    }));
  } catch (err) {
    errorResponse(res, 500, "Internal Server Error");
  }
});

router.delete("/admin/sessions/:id", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    await col("sessions").deleteOne({ _id: id as unknown } as Record<string, unknown>);
    res.json({ ok: true });
  } catch (err) {
    errorResponse(res, 500, "Internal Server Error");
  }
});

// ── Login History ─────────────────────────────────────────────────────────────

router.get("/audit-log/logins", requireAuth, async (req, res) => {
  try {
    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const userId = session.userId;
    const isAdmin = session.role === "admin";
    const query: Record<string, unknown> = { action: { $in: ["user.login", "user.login_failed", "user.saml_login", "user.logout"] } };
    if (!isAdmin) query["user_id"] = userId;
    const logs = await col("audit_log").find(query).sort({ created_at: -1 }).limit(100).toArray();
    res.json(logs.map(l => ({
      id: String(l["_id"]),
      user_id: l["user_id"],
      username: l["username"],
      action: l["action"],
      ip: l["ip"],
      details: l["details"],
      created_at: l["created_at"],
    })));
  } catch (err) {
    errorResponse(res, 500, "Internal Server Error");
  }
});

router.get("/admin/login-history", requireAuth, async (req, res) => {
  try {
    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const userId = session.userId;
    const isAdmin = session.role === "admin";
    const query: Record<string, unknown> = { action: { $in: ["user.login", "user.login_failed", "user.saml_login", "user.logout"] } };
    if (!isAdmin) query["user_id"] = userId;
    const logs = await col("audit_log").find(query).sort({ created_at: -1 }).limit(100).toArray();
    res.json(logs.map(l => {
      const details = l["details"] as Record<string, unknown> | undefined;
      const action = String(l["action"] ?? "");
      return {
        id: String(l["_id"]),
        user_email: details?.["user_email"] ?? l["username"] ?? "unknown",
        username: l["username"] ?? "unknown",
        ip: l["ip"] ?? "",
        user_agent: details?.["user_agent"] ?? "",
        success: !action.includes("failed"),
        action,
        timestamp: l["created_at"],
        created_at: l["created_at"],
      };
    }));
  } catch (err) {
    errorResponse(res, 500, "Internal Server Error");
  }
});

// ── Audit Log Export ──────────────────────────────────────────────────────────

router.get("/admin/audit-log/export", requireAdmin, async (req, res) => {
  try {
    const from = req.query["from"] ? new Date(String(req.query["from"])) : new Date(Date.now() - 30 * 86400000);
    const to = req.query["to"] ? new Date(String(req.query["to"])) : new Date();
    const action = req.query["action"] as string | undefined;

    const query: Record<string, unknown> = { created_at: { $gte: from, $lte: to } };
    if (action) query["action"] = action;

    const logs = await col("audit_log").find(query).sort({ created_at: -1 }).limit(10000).toArray();

    const headers = ["created_at", "user_id", "username", "action", "resource", "resource_id", "ip", "details"];
    const escape = (v: unknown) => { const s = String(v ?? "").replace(/"/g, '""'); return s.includes(",") || s.includes("\n") ? `"${s}"` : s; };
    const rows = [
      headers.join(","),
      ...logs.map(l => headers.map(h => escape(h === "details" ? JSON.stringify(l[h]) : l[h])).join(",")),
    ];

    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", `attachment; filename="audit-log-${Date.now()}.csv"`);
    res.send(rows.join("\n"));
  } catch (err) {
    errorResponse(res, 500, "Internal Server Error");
  }
});

// ── Platform Policy Settings ──────────────────────────────────────────────────

router.get("/admin/policy", requireAdmin, async (_req, res) => {
  try {
    const policy = await col("platform_policy").findOne({}) as Record<string, unknown> | null;
    res.json(policy ?? {
      enforce_2fa: false,
      session_timeout_minutes: 480,
      data_retention_days: 365,
      max_failed_logins: 5,
      password_min_length: 12,
    });
  } catch (err) {
    errorResponse(res, 500, "Internal Server Error");
  }
});

router.patch("/admin/policy", requireAdmin, async (req, res) => {
  try {
    const updates = req.body as Record<string, unknown>;
    await col("platform_policy").updateOne(
      {},
      { $set: { ...updates, updated_at: new Date() } },
      { upsert: true }
    );
    const policy = await col("platform_policy").findOne({});
    res.json(policy);
  } catch (err) {
    errorResponse(res, 500, "Internal Server Error");
  }
});

// ── SAML Configuration ────────────────────────────────────────────────────────

router.get("/admin/saml-config", requireAdmin, async (_req, res) => {
  res.json({
    callback_url: process.env["SAML_CALLBACK_URL"] ?? "",
    entry_point: process.env["SAML_ENTRY_POINT"] ?? "",
    issuer: process.env["SAML_ISSUER"] ?? "bugfinder",
    idp_cert_configured: !!(process.env["SAML_IDP_CERT"] ?? ""),
    private_key_configured: !!(process.env["SAML_PRIVATE_KEY"] ?? ""),
    metadata_url: "/api/auth/saml/metadata",
    login_url: "/api/auth/saml/login",
    enabled: !!(process.env["SAML_ENTRY_POINT"] ?? ""),
  });
});

// ── Tenant Management ─────────────────────────────────────────────────────────

router.get("/admin/tenants", requireAdmin, async (req, res) => {
  try {
    const tenants = await col("tenants").find({}).sort({ created_at: -1 }).toArray() as Array<Record<string, unknown>>;
    res.json(tenants.map(t => ({
      id: String(t["_id"]),
      name: t["name"],
      owner_email: t["owner_email"],
      active: t["active"] ?? true,
      max_concurrent_scans: t["max_concurrent_scans"] ?? 5,
      max_findings_stored: t["max_findings_stored"] ?? 10000,
      storage_limit_gb: t["storage_limit_gb"] ?? 10,
      created_at: t["created_at"],
      updated_at: t["updated_at"],
    })));
  } catch (err) {
    logger.error({ err }, "List tenants error");
    errorResponse(res, 500, "Internal Server Error");
  }
});

router.post("/admin/tenants", requireAdmin, async (req, res) => {
  try {
    const { name, owner_email } = req.body as { name?: string; owner_email?: string };
    if (!name) return errorResponse(res, 400, "name is required");
    const existing = await col("tenants").findOne({ name } as Record<string, unknown>);
    if (existing) return errorResponse(res, 409, "A tenant with this name already exists");
    const doc = {
      name,
      owner_email: owner_email ?? "",
      active: true,
      max_concurrent_scans: 5,
      max_findings_stored: 10000,
      storage_limit_gb: 10,
      created_at: new Date(),
      updated_at: new Date(),
    };
    const insert = await col("tenants").insertOne(doc);
    const tenant = await col("tenants").findOne({ _id: insert.insertedId }) as Record<string, unknown>;
    res.status(201).json({
      id: String(tenant["_id"]),
      name: tenant["name"],
      owner_email: tenant["owner_email"],
      active: tenant["active"],
      max_concurrent_scans: tenant["max_concurrent_scans"],
      max_findings_stored: tenant["max_findings_stored"],
      storage_limit_gb: tenant["storage_limit_gb"],
      created_at: tenant["created_at"],
      updated_at: tenant["updated_at"],
    });
  } catch (err) {
    logger.error({ err }, "Create tenant error");
    errorResponse(res, 500, "Internal Server Error");
  }
});

router.patch("/admin/tenants/:id", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return errorResponse(res, 404, "Not Found");
    const { active } = req.body as { active?: boolean };
    const update: Record<string, unknown> = { updated_at: new Date() };
    if (active !== undefined) update["active"] = active;
    await col("tenants").updateOne({ _id: new ObjectId(id) } as Record<string, unknown>, { $set: update });
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "Update tenant error");
    errorResponse(res, 500, "Internal Server Error");
  }
});

router.delete("/admin/tenants/:id", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params["id"]);
    if (!ObjectId.isValid(id)) return errorResponse(res, 404, "Not Found");
    await col("tenants").deleteOne({ _id: new ObjectId(id) } as Record<string, unknown>);
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "Delete tenant error");
    errorResponse(res, 500, "Internal Server Error");
  }
});

router.put("/admin/tenants/:tenantId/quota", requireAdmin, async (req, res) => {
  try {
    const tenantId = String(req.params["tenantId"]);
    if (!ObjectId.isValid(tenantId)) return errorResponse(res, 404, "Not Found");
    const { max_concurrent_scans, max_findings_stored, storage_limit_gb } = req.body as {
      max_concurrent_scans?: number; max_findings_stored?: number; storage_limit_gb?: number;
    };
    const update: Record<string, unknown> = { updated_at: new Date() };
    if (max_concurrent_scans !== undefined) update["max_concurrent_scans"] = max_concurrent_scans;
    if (max_findings_stored !== undefined) update["max_findings_stored"] = max_findings_stored;
    if (storage_limit_gb !== undefined) update["storage_limit_gb"] = storage_limit_gb;
    await col("tenants").updateOne({ _id: new ObjectId(tenantId) } as Record<string, unknown>, { $set: update });
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "Update tenant quota error");
    errorResponse(res, 500, "Internal Server Error");
  }
});

export default router;
