import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";

const router = Router();

function formatTemplate(t: Record<string, unknown>) {
  return {
    id: String(t["_id"]),
    name: t["name"],
    description: t["description"] ?? "",
    scan_profile: t["scan_profile"] ?? "standard",
    validation_enabled: t["validation_enabled"] ?? false,
    fuzzing_enabled: t["fuzzing_enabled"] ?? false,
    bug_bounty_mode: t["bug_bounty_mode"] ?? false,
    custom_headers: t["custom_headers"] ?? {},
    auth_headers: t["auth_headers"] ?? {},
    scope_hosts: t["scope_hosts"] ?? [],
    tags: t["tags"] ?? [],
    is_builtin: t["is_builtin"] ?? false,
    created_at: t["created_at"],
    updated_at: t["updated_at"],
  };
}

// GET /scan-templates
router.get("/scan-templates", async (req, res) => {
  try {
    const templates = await col("scan_templates").find({}).sort({ created_at: 1 }).toArray() as Array<Record<string, unknown>>;

    // Seed built-in templates if collection is empty
    if (templates.length === 0) {
      const now = new Date();
      const builtins = [
        { name: "Quick Recon", description: "Fast reconnaissance: TLS, headers, cookies, recon, DNS, JS secrets, CVE lookup", scan_profile: "quick", validation_enabled: false, fuzzing_enabled: false, bug_bounty_mode: false, tags: ["recon", "fast"], is_builtin: true, created_at: now, updated_at: now },
        { name: "Standard Security Audit", description: "Full security audit including CORS, XSS, SQLi, JWT, rate limits, GraphQL", scan_profile: "standard", validation_enabled: true, fuzzing_enabled: false, bug_bounty_mode: false, tags: ["audit", "standard"], is_builtin: true, created_at: now, updated_at: now },
        { name: "Bug Bounty Deep Dive", description: "Deep scan with IDOR, auth testing, SSRF, SSTI, file upload, subdomain enum, Wayback Machine", scan_profile: "deep", validation_enabled: true, fuzzing_enabled: true, bug_bounty_mode: true, tags: ["bounty", "deep", "full"], is_builtin: true, created_at: now, updated_at: now },
        { name: "API Security Test", description: "Focused API security: JWT attacks, GraphQL checks, rate limiting, CORS", scan_profile: "standard", validation_enabled: false, fuzzing_enabled: false, bug_bounty_mode: false, tags: ["api", "jwt", "graphql"], is_builtin: true, created_at: now, updated_at: now },
        { name: "OWASP Top 10 Scan", description: "Covers OWASP Top 10: injection, auth, XSS, IDOR, security misconfiguration", scan_profile: "standard", validation_enabled: true, fuzzing_enabled: true, bug_bounty_mode: true, tags: ["owasp", "compliance"], is_builtin: true, created_at: now, updated_at: now },
      ];
      for (const t of builtins) {
        await col("scan_templates").insertOne(t);
      }
      const all = await col("scan_templates").find({}).sort({ created_at: 1 }).toArray() as Array<Record<string, unknown>>;
      return res.json(all.map(formatTemplate));
    }

    res.json(templates.map(formatTemplate));
  } catch (err) {
    logger.error({ err }, "List scan templates error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /scan-templates
router.post("/scan-templates", async (req, res) => {
  try {
    const body = req.body as {
      name: string;
      description?: string;
      scan_profile: string;
      validation_enabled?: boolean;
      fuzzing_enabled?: boolean;
      bug_bounty_mode?: boolean;
      custom_headers?: Record<string, string>;
      auth_headers?: Record<string, string>;
      scope_hosts?: string[];
      tags?: string[];
    };

    if (!body.name || !body.scan_profile) {
      return res.status(400).json({ error: "name and scan_profile are required" });
    }

    const now = new Date();
    const insert = await col("scan_templates").insertOne({
      name: body.name,
      description: body.description ?? "",
      scan_profile: body.scan_profile,
      validation_enabled: body.validation_enabled ?? false,
      fuzzing_enabled: body.fuzzing_enabled ?? false,
      bug_bounty_mode: body.bug_bounty_mode ?? false,
      custom_headers: body.custom_headers ?? {},
      auth_headers: body.auth_headers ?? {},
      scope_hosts: body.scope_hosts ?? [],
      tags: body.tags ?? [],
      is_builtin: false,
      created_at: now,
      updated_at: now,
    });

    const tmpl = await col("scan_templates").findOne({ _id: insert.insertedId } as Record<string, unknown>) as Record<string, unknown>;
    res.status(201).json(formatTemplate(tmpl));
  } catch (err) {
    logger.error({ err }, "Create scan template error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// PUT /scan-templates/:id
router.put("/scan-templates/:id", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const body = req.body as Record<string, unknown>;
    const existing = await col("scan_templates").findOne({ _id: new ObjectId(id) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!existing) return res.status(404).json({ error: "Template not found" });
    if (existing["is_builtin"]) return res.status(403).json({ error: "Cannot edit built-in templates" });

    const updates: Record<string, unknown> = { updated_at: new Date() };
    const allowed = ["name", "description", "scan_profile", "validation_enabled", "fuzzing_enabled", "bug_bounty_mode", "custom_headers", "auth_headers", "scope_hosts", "tags"];
    for (const key of allowed) {
      if (key in body) updates[key] = body[key];
    }

    await col("scan_templates").updateOne({ _id: new ObjectId(id) } as Record<string, unknown>, { $set: updates });
    const updated = await col("scan_templates").findOne({ _id: new ObjectId(id) } as Record<string, unknown>) as Record<string, unknown>;
    res.json(formatTemplate(updated));
  } catch (err) {
    logger.error({ err }, "Update scan template error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// DELETE /scan-templates/:id
router.delete("/scan-templates/:id", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const existing = await col("scan_templates").findOne({ _id: new ObjectId(id) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!existing) return res.status(404).json({ error: "Template not found" });
    if (existing["is_builtin"]) return res.status(403).json({ error: "Cannot delete built-in templates" });

    await col("scan_templates").deleteOne({ _id: new ObjectId(id) } as Record<string, unknown>);
    res.status(204).send();
  } catch (err) {
    logger.error({ err }, "Delete scan template error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
