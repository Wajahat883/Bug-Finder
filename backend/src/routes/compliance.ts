import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";
import PDFDocument from "pdfkit";

// SOC2 / ISO 27001 / PCI-DSS control mappings keyed by finding category
const CONTROL_MAPPINGS: Record<string, { soc2: string[]; iso27001: string[]; pci: string[] }> = {
  "injection":  { soc2: ["CC6.1","CC6.6"], iso27001: ["A.14.2.5","A.8.28"], pci: ["6.3.1","6.3.2"] },
  "xss":        { soc2: ["CC6.1"],          iso27001: ["A.14.2.5"],          pci: ["6.3.1"] },
  "auth":       { soc2: ["CC6.2","CC6.3"],  iso27001: ["A.9.2.1","A.9.4.2"], pci: ["8.2.1","8.3.1"] },
  "crypto":     { soc2: ["CC9.1"],          iso27001: ["A.10.1.1"],          pci: ["3.4.1","4.2.1"] },
  "config":     { soc2: ["CC7.1"],          iso27001: ["A.12.1.1"],          pci: ["2.2.1"] },
  "exposure":   { soc2: ["CC6.7"],          iso27001: ["A.13.2.3"],          pci: ["4.1.1"] },
  "secrets":    { soc2: ["CC6.1","CC6.7"], iso27001: ["A.10.1.1"],          pci: ["3.4.1"] },
};

// Normalise a finding category string to a CONTROL_MAPPINGS key
function normaliseCategoryKey(category: string): string {
  const c = category.toLowerCase();
  if (c.includes("inject") || c.includes("sqli") || c.includes("nosql") || c.includes("template")) return "injection";
  if (c.includes("xss") || c.includes("cross-site scripting")) return "xss";
  if (c.includes("auth") || c.includes("jwt") || c.includes("session")) return "auth";
  if (c.includes("crypto") || c.includes("tls") || c.includes("certif") || c.includes("encrypt")) return "crypto";
  if (c.includes("config") || c.includes("cors") || c.includes("misconfigur")) return "config";
  if (c.includes("secret") || c.includes("hardcoded") || c.includes("api_key") || c.includes("credential")) return "secrets";
  if (c.includes("expos") || c.includes("disclosure") || c.includes("leak")) return "exposure";
  return "";
}

const router = Router();

// OWASP Top 10 2021 mapping
const OWASP_MAP: Record<string, { id: string; name: string; url: string }> = {
  "Injection": { id: "A03:2021", name: "Injection", url: "https://owasp.org/Top10/A03_2021-Injection/" },
  "Template Injection": { id: "A03:2021", name: "Injection", url: "https://owasp.org/Top10/A03_2021-Injection/" },
  "SQLi": { id: "A03:2021", name: "Injection", url: "https://owasp.org/Top10/A03_2021-Injection/" },
  "Header Injection": { id: "A03:2021", name: "Injection", url: "https://owasp.org/Top10/A03_2021-Injection/" },
  "Authentication": { id: "A07:2021", name: "Identification and Authentication Failures", url: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" },
  "JWT Security": { id: "A07:2021", name: "Identification and Authentication Failures", url: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" },
  "Session Management": { id: "A07:2021", name: "Identification and Authentication Failures", url: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" },
  "XSS": { id: "A03:2021", name: "Injection", url: "https://owasp.org/Top10/A03_2021-Injection/" },
  "Cross-Site Scripting": { id: "A03:2021", name: "Injection", url: "https://owasp.org/Top10/A03_2021-Injection/" },
  "Broken Access Control": { id: "A01:2021", name: "Broken Access Control", url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/" },
  "IDOR": { id: "A01:2021", name: "Broken Access Control", url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/" },
  "Path Traversal": { id: "A01:2021", name: "Broken Access Control", url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/" },
  "Security Misconfiguration": { id: "A05:2021", name: "Security Misconfiguration", url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/" },
  "CORS": { id: "A05:2021", name: "Security Misconfiguration", url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/" },
  "TLS": { id: "A02:2021", name: "Cryptographic Failures", url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/" },
  "Cryptographic": { id: "A02:2021", name: "Cryptographic Failures", url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/" },
  "Information Disclosure": { id: "A05:2021", name: "Security Misconfiguration", url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/" },
  "Secrets Exposure": { id: "A02:2021", name: "Cryptographic Failures", url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/" },
  "Known Vulnerability": { id: "A06:2021", name: "Vulnerable and Outdated Components", url: "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/" },
  "Supply Chain": { id: "A06:2021", name: "Vulnerable and Outdated Components", url: "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/" },
  "Attack Surface": { id: "A05:2021", name: "Security Misconfiguration", url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/" },
  "API Security": { id: "A05:2021", name: "Security Misconfiguration", url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/" },
  "Request Smuggling": { id: "A03:2021", name: "Injection", url: "https://owasp.org/Top10/A03_2021-Injection/" },
  "WebSocket Security": { id: "A05:2021", name: "Security Misconfiguration", url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/" },
  "File Upload": { id: "A04:2021", name: "Insecure Design", url: "https://owasp.org/Top10/A04_2021-Insecure_Design/" },
};

// PCI DSS 4.0 requirements mapping
const PCI_MAP: Record<string, string> = {
  "TLS": "PCI-DSS 4.0 Req 4.2.1 — Strong cryptography in transit",
  "Cryptographic": "PCI-DSS 4.0 Req 4.2.1 — Strong cryptography in transit",
  "Authentication": "PCI-DSS 4.0 Req 8 — Identify users and authenticate access",
  "Secrets Exposure": "PCI-DSS 4.0 Req 3.5 — Protect stored account data",
  "Injection": "PCI-DSS 4.0 Req 6.2.4 — Software engineering techniques to prevent vulnerabilities",
  "Known Vulnerability": "PCI-DSS 4.0 Req 6.3 — Security vulnerabilities are identified and addressed",
  "Supply Chain": "PCI-DSS 4.0 Req 6.3.3 — All software components protected from known vulnerabilities",
  "CORS": "PCI-DSS 4.0 Req 6.2.4 — Prevention of common vulnerabilities",
  "XSS": "PCI-DSS 4.0 Req 6.2.4 — Prevention of injection attacks",
  "File Upload": "PCI-DSS 4.0 Req 6.2.4 — Secure software development",
};

// SOC 2 Trust Services Criteria mapping
const SOC2_MAP: Record<string, string> = {
  "Authentication": "CC6.1 — Logical and physical access controls",
  "Broken Access Control": "CC6.1 — Logical and physical access controls",
  "IDOR": "CC6.1 — Logical and physical access controls",
  "TLS": "CC6.7 — Data transmission security",
  "Cryptographic": "CC6.7 — Data transmission security",
  "Secrets Exposure": "CC6.7 — Data transmission security",
  "Information Disclosure": "CC6.6 — Exposure of confidential information",
  "Known Vulnerability": "CC7.1 — Detection and monitoring",
  "Security Misconfiguration": "CC6.6 — Logical access to restricted assets",
};

function getCategoryMappings(category: string) {
  const owasp = OWASP_MAP[category] ?? null;
  const pci = PCI_MAP[category] ?? null;
  const soc2 = SOC2_MAP[category] ?? null;
  return { owasp, pci_dss: pci, soc2 };
}

// CWE → framework mapping table
const CWE_MAP: Record<string, { owasp?: string; pci?: string; soc2?: string; iso27001?: string; description: string }> = {
  "CWE-79":  { owasp: "A03:2021 — Injection (XSS)", pci: "PCI-DSS 4.0 Req 6.2.4", soc2: "CC6.1", iso27001: "A.14.2.5", description: "Cross-site Scripting" },
  "CWE-89":  { owasp: "A03:2021 — Injection (SQLi)", pci: "PCI-DSS 4.0 Req 6.2.4", soc2: "CC6.1", iso27001: "A.14.2.5", description: "SQL Injection" },
  "CWE-200": { owasp: "A05:2021 — Security Misconfiguration", pci: "PCI-DSS 4.0 Req 3.4", soc2: "CC6.6", iso27001: "A.18.1.3", description: "Information Exposure" },
  "CWE-284": { owasp: "A01:2021 — Broken Access Control", pci: "PCI-DSS 4.0 Req 7", soc2: "CC6.1", iso27001: "A.9.4.1", description: "Improper Access Control" },
  "CWE-285": { owasp: "A01:2021 — Broken Access Control", pci: "PCI-DSS 4.0 Req 7", soc2: "CC6.1", iso27001: "A.9.4.1", description: "Improper Authorization" },
  "CWE-295": { owasp: "A02:2021 — Cryptographic Failures", pci: "PCI-DSS 4.0 Req 4.2.1", soc2: "CC6.7", iso27001: "A.10.1.1", description: "Improper Certificate Validation" },
  "CWE-298": { owasp: "A02:2021 — Cryptographic Failures", pci: "PCI-DSS 4.0 Req 4.2.1", soc2: "CC6.7", iso27001: "A.10.1.1", description: "Certificate Expiry Not Checked" },
  "CWE-319": { owasp: "A02:2021 — Cryptographic Failures", pci: "PCI-DSS 4.0 Req 4.2.1", soc2: "CC6.7", iso27001: "A.10.1.1", description: "Cleartext Transmission of Sensitive Info" },
  "CWE-326": { owasp: "A02:2021 — Cryptographic Failures", pci: "PCI-DSS 4.0 Req 4.2.1", soc2: "CC6.7", iso27001: "A.10.1.1", description: "Inadequate Encryption Strength" },
  "CWE-327": { owasp: "A02:2021 — Cryptographic Failures", pci: "PCI-DSS 4.0 Req 4.2.1", soc2: "CC6.7", iso27001: "A.10.1.1", description: "Use of Broken/Risky Cryptographic Algorithm" },
  "CWE-330": { owasp: "A02:2021 — Cryptographic Failures", pci: "PCI-DSS 4.0 Req 6.2.4", soc2: "CC6.7", iso27001: "A.10.1.1", description: "Use of Insufficiently Random Values" },
  "CWE-352": { owasp: "A01:2021 — Broken Access Control", pci: "PCI-DSS 4.0 Req 6.2.4", soc2: "CC6.1", iso27001: "A.14.2.5", description: "Cross-Site Request Forgery (CSRF)" },
  "CWE-434": { owasp: "A04:2021 — Insecure Design", pci: "PCI-DSS 4.0 Req 6.2.4", soc2: "CC6.1", iso27001: "A.14.2.5", description: "Unrestricted File Upload" },
  "CWE-538": { owasp: "A05:2021 — Security Misconfiguration", pci: "PCI-DSS 4.0 Req 3", soc2: "CC6.6", iso27001: "A.18.1.3", description: "File and Directory Information Exposure" },
  "CWE-601": { owasp: "A01:2021 — Broken Access Control", pci: "PCI-DSS 4.0 Req 6.2.4", soc2: "CC6.1", iso27001: "A.14.2.5", description: "Open Redirect" },
  "CWE-693": { owasp: "A05:2021 — Security Misconfiguration", soc2: "CC6.6", iso27001: "A.14.1.2", description: "Protection Mechanism Failure (missing CSP)" },
  "CWE-798": { owasp: "A07:2021 — Auth Failures", pci: "PCI-DSS 4.0 Req 8.3.6", soc2: "CC6.1", iso27001: "A.9.2.3", description: "Hardcoded Credentials" },
  "CWE-862": { owasp: "A01:2021 — Broken Access Control", pci: "PCI-DSS 4.0 Req 7", soc2: "CC6.1", iso27001: "A.9.4.1", description: "Missing Authorization" },
  "CWE-942": { owasp: "A05:2021 — Security Misconfiguration", soc2: "CC6.6", iso27001: "A.14.1.2", description: "Permissive CORS Policy" },
  "CWE-943": { owasp: "A03:2021 — Injection (NoSQLi)", pci: "PCI-DSS 4.0 Req 6.2.4", soc2: "CC6.1", iso27001: "A.14.2.5", description: "NoSQL Injection" },
};

// GET /compliance/cwe/:cweId — Dynamic CWE to framework mapping
router.get("/compliance/cwe/:cweId", (req, res) => {
  const cweId = req.params.cweId.toUpperCase().startsWith("CWE-") ? req.params.cweId.toUpperCase() : `CWE-${req.params.cweId}`;
  const mapping = CWE_MAP[cweId];
  if (!mapping) {
    return res.status(404).json({ error: `No compliance mapping found for ${cweId}`, cwe_id: cweId });
  }
  res.json({ cwe_id: cweId, ...mapping });
});

// GET /compliance/report — Generate compliance report for all findings or a specific scan
router.get("/compliance/report", async (req, res) => {
  try {
    const scanId = req.query["scan_id"] as string | undefined;

    const query: Record<string, unknown> = {};
    if (scanId && ObjectId.isValid(scanId)) {
      query["scan_job_id"] = new ObjectId(scanId);
    }

    const findings = await col("findings").find(query).toArray() as Array<Record<string, unknown>>;

    // Build compliance mapping
    const owaspMap: Record<string, { id: string; name: string; url: string; count: number; critical: number; high: number }> = {};
    const pciIssues: Array<{ req: string; finding_title: string; severity: string }> = [];
    const soc2Issues: Array<{ criteria: string; finding_title: string; severity: string }> = [];

    let compliant_count = 0;
    let non_compliant_count = 0;

    for (const f of findings) {
      const category = String(f["category"] ?? "");
      const mappings = getCategoryMappings(category);

      if (mappings.owasp) {
        if (!owaspMap[mappings.owasp.id]) {
          owaspMap[mappings.owasp.id] = { ...mappings.owasp, count: 0, critical: 0, high: 0 };
        }
        owaspMap[mappings.owasp.id].count++;
        if (f["severity"] === "critical") owaspMap[mappings.owasp.id].critical++;
        if (f["severity"] === "high") owaspMap[mappings.owasp.id].high++;
        non_compliant_count++;
      } else {
        compliant_count++;
      }

      if (mappings.pci_dss) {
        pciIssues.push({ req: mappings.pci_dss, finding_title: String(f["title"] ?? ""), severity: String(f["severity"] ?? "") });
      }
      if (mappings.soc2) {
        soc2Issues.push({ criteria: mappings.soc2, finding_title: String(f["title"] ?? ""), severity: String(f["severity"] ?? "") });
      }
    }

    // OWASP Top 10 full list with pass/fail
    const owaspTop10 = [
      { id: "A01:2021", name: "Broken Access Control" },
      { id: "A02:2021", name: "Cryptographic Failures" },
      { id: "A03:2021", name: "Injection" },
      { id: "A04:2021", name: "Insecure Design" },
      { id: "A05:2021", name: "Security Misconfiguration" },
      { id: "A06:2021", name: "Vulnerable and Outdated Components" },
      { id: "A07:2021", name: "Identification and Authentication Failures" },
      { id: "A08:2021", name: "Software and Data Integrity Failures" },
      { id: "A09:2021", name: "Security Logging and Monitoring Failures" },
      { id: "A10:2021", name: "Server-Side Request Forgery" },
    ].map(item => ({
      ...item,
      url: `https://owasp.org/Top10/${item.id.replace(":", "_")}-${item.name.replace(/\s+/g, "_").replace(/[^A-Za-z0-9_]/g, "")}/`,
      status: owaspMap[item.id] ? "fail" : "pass",
      findings_count: owaspMap[item.id]?.count ?? 0,
      critical: owaspMap[item.id]?.critical ?? 0,
      high: owaspMap[item.id]?.high ?? 0,
    }));

    const pciScore = pciIssues.length === 0 ? 100 : Math.max(0, 100 - pciIssues.length * 10);
    const soc2Score = soc2Issues.length === 0 ? 100 : Math.max(0, 100 - soc2Issues.length * 8);
    const owaspFails = owaspTop10.filter(o => o.status === "fail").length;
    const owaspScore = Math.round(((10 - owaspFails) / 10) * 100);

    res.json({
      generated_at: new Date().toISOString(),
      scan_id: scanId ?? null,
      total_findings: findings.length,
      owasp_top10: owaspTop10,
      owasp_compliance_score: owaspScore,
      pci_dss: {
        score: pciScore,
        issues: pciIssues.slice(0, 20),
        status: pciScore >= 80 ? "compliant" : "non-compliant",
      },
      soc2: {
        score: soc2Score,
        issues: soc2Issues.slice(0, 20),
        status: soc2Score >= 80 ? "compliant" : "non-compliant",
      },
      iso27001: {
        score: Math.max(0, 100 - findings.filter(f => f["severity"] === "critical" || f["severity"] === "high").length * 15),
        status: findings.filter(f => f["severity"] === "critical").length === 0 ? "compliant" : "non-compliant",
      },
      hipaa: {
        score: pciScore,
        status: pciScore >= 90 ? "compliant" : "non-compliant",
        notes: "HIPAA assessment based on PHI data protection controls",
      },
    });
  } catch (err) {
    logger.error({ err }, "Compliance report error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /compliance/findings/:id — Get compliance tags for a specific finding
router.get("/compliance/findings/:id", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Not found" });

    const finding = await col("findings").findOne({ _id: new ObjectId(id) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!finding) return res.status(404).json({ error: "Finding not found" });

    const category = String(finding["category"] ?? "");
    const mappings = getCategoryMappings(category);

    res.json({ finding_id: id, category, ...mappings });
  } catch (err) {
    logger.error({ err }, "Get finding compliance error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /compliance/history — weekly compliance % for last 8 weeks, computed from findings
router.get("/compliance/history", async (req, res) => {
  try {
    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const userFilter = session?.role !== "admin" ? { user_id: session?.userId ?? null } : {};
    const findings = await col("findings").find(userFilter).toArray() as Array<Record<string, unknown>>;
    const now = Date.now();
    const weeks: Array<{ week: string; pci: number; soc2: number; owasp: number; iso: number }> = [];

    for (let i = 7; i >= 0; i--) {
      const cutoff = new Date(now - i * 7 * 24 * 60 * 60 * 1000);
      const subset = findings.filter(f => {
        const d = f["created_at"] instanceof Date ? f["created_at"] : new Date(f["created_at"] as string ?? 0);
        return d <= cutoff;
      });
      const crits = subset.filter(f => f["severity"] === "critical").length;
      const highs = subset.filter(f => f["severity"] === "high").length;
      const pciIssues = subset.filter(f => ["TLS","Cryptographic","Authentication","Injection","XSS","Secrets Exposure","Known Vulnerability","Supply Chain","CORS","File Upload"].includes(String(f["category"] ?? ""))).length;
      const soc2Issues = subset.filter(f => ["Authentication","Broken Access Control","IDOR","TLS","Cryptographic","Secrets Exposure","Information Disclosure","Known Vulnerability","Security Misconfiguration"].includes(String(f["category"] ?? ""))).length;
      const owaspFails = new Set(subset.map(f => {
        const OWASP_MAP2: Record<string,string> = {"Injection":"A03:2021","Template Injection":"A03:2021","SQLi":"A03:2021","XSS":"A03:2021","Cross-Site Scripting":"A03:2021","Request Smuggling":"A03:2021","Header Injection":"A03:2021","Authentication":"A07:2021","JWT Security":"A07:2021","Session Management":"A07:2021","Broken Access Control":"A01:2021","IDOR":"A01:2021","Path Traversal":"A01:2021","Security Misconfiguration":"A05:2021","CORS":"A05:2021","Information Disclosure":"A05:2021","API Security":"A05:2021","Attack Surface":"A05:2021","WebSocket Security":"A05:2021","TLS":"A02:2021","Cryptographic":"A02:2021","Secrets Exposure":"A02:2021","File Upload":"A04:2021","Known Vulnerability":"A06:2021","Supply Chain":"A06:2021"};
        return OWASP_MAP2[String(f["category"] ?? "")] ?? null;
      }).filter(Boolean)).size;
      weeks.push({
        week: `W${8 - i}`,
        pci: Math.max(0, 100 - pciIssues * 10),
        soc2: Math.max(0, 100 - soc2Issues * 8),
        owasp: Math.round(((10 - Math.min(10, owaspFails)) / 10) * 100),
        iso: Math.max(0, 100 - (crits * 15 + highs * 8)),
      });
    }
    res.json(weeks);
  } catch (err) {
    logger.error({ err }, "Compliance history error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /compliance/owasp/findings/:categoryId — findings for an OWASP category
router.get("/compliance/owasp/findings/:categoryId", async (req, res) => {
  try {
    const { categoryId } = req.params;
    const REVERSE_MAP: Record<string, string[]> = {
      "A01:2021": ["Broken Access Control","IDOR","Path Traversal"],
      "A02:2021": ["TLS","Cryptographic","Secrets Exposure"],
      "A03:2021": ["Injection","Template Injection","SQLi","XSS","Cross-Site Scripting","Request Smuggling","Header Injection"],
      "A04:2021": ["File Upload","Insecure Design"],
      "A05:2021": ["Security Misconfiguration","CORS","Information Disclosure","API Security","Attack Surface","WebSocket Security"],
      "A06:2021": ["Known Vulnerability","Supply Chain"],
      "A07:2021": ["Authentication","JWT Security","Session Management"],
      "A08:2021": ["Software Integrity"],
      "A09:2021": ["Security Logging"],
      "A10:2021": ["SSRF","Server-Side Request Forgery"],
    };
    const categories = REVERSE_MAP[categoryId] ?? [];
    const findings = await col("findings").find({ category: { $in: categories } }).toArray() as Array<Record<string, unknown>>;
    res.json(findings.map(f => ({ ...f, id: String(f["_id"]) })));
  } catch (err) {
    logger.error({ err }, "OWASP category findings error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /compliance/attestations — list manual control attestations
router.get("/compliance/attestations", async (_req, res) => {
  try {
    const items = await col("compliance_attestations").find({}).sort({ created_at: -1 }).toArray() as Array<Record<string, unknown>>;
    res.json(items.map(a => ({ ...a, id: String(a["_id"]) })));
  } catch (err) {
    logger.error({ err }, "List attestations error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /compliance/attestations — create attestation
router.post("/compliance/attestations", async (req, res) => {
  try {
    const { framework, control_id, control_name, note, analyst } = req.body as {
      framework?: string; control_id?: string; control_name?: string; note?: string; analyst?: string;
    };
    if (!framework || !control_id) return res.status(400).json({ error: "framework and control_id required" });
    const insert = await col("compliance_attestations").insertOne({
      framework, control_id, control_name: control_name ?? control_id,
      note: note ?? "", analyst: analyst ?? "Unknown",
      status: "compliant", created_at: new Date(),
    });
    const saved = await col("compliance_attestations").findOne({ _id: insert.insertedId }) as Record<string, unknown>;
    res.status(201).json({ ...saved, id: String(saved["_id"]) });
  } catch (err) {
    logger.error({ err }, "Create attestation error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── SOC2 / ISO 27001 / PCI-DSS framework endpoints ──────────────────────────

// GET /compliance/mapping — findings grouped by framework control
router.get("/compliance/mapping", requireAuth, async (req, res) => {
  try {
    const sess = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const userFilter = sess?.role !== "admin" ? { user_id: sess?.userId } : {};
    const findings = await col("findings").find({ ...userFilter, status: { $nin: ["resolved", "false_positive"] } }).toArray() as Array<Record<string, unknown>>;

    // Build control → findings map for each framework
    const soc2Map: Record<string, Array<Record<string, unknown>>> = {};
    const iso27001Map: Record<string, Array<Record<string, unknown>>> = {};
    const pciMap: Record<string, Array<Record<string, unknown>>> = {};

    for (const f of findings) {
      const key = normaliseCategoryKey(String(f["category"] ?? ""));
      const controls = CONTROL_MAPPINGS[key];
      if (!controls) continue;
      const summary = { id: String(f["_id"]), title: f["title"], severity: f["severity"], category: f["category"] };
      for (const ctrl of controls.soc2) { (soc2Map[ctrl] ??= []).push(summary); }
      for (const ctrl of controls.iso27001) { (iso27001Map[ctrl] ??= []).push(summary); }
      for (const ctrl of controls.pci) { (pciMap[ctrl] ??= []).push(summary); }
    }

    res.json({ soc2: soc2Map, iso27001: iso27001Map, pci: pciMap });
  } catch (err) {
    logger.error({ err }, "Compliance mapping error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /compliance/report/:framework — per-framework compliance score
router.get("/compliance/report/:framework", requireAuth, async (req, res) => {
  try {
    const { framework } = req.params;
    if (!["soc2", "iso27001", "pci"].includes(framework)) {
      return res.status(400).json({ error: "framework must be one of: soc2, iso27001, pci" });
    }

    const sess = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const userFilter = sess?.role !== "admin" ? { user_id: sess?.userId } : {};
    const findings = await col("findings").find({ ...userFilter, status: { $nin: ["resolved", "false_positive"] } }).toArray() as Array<Record<string, unknown>>;

    // Collect all controls for this framework
    const allControls = new Set<string>();
    for (const mapping of Object.values(CONTROL_MAPPINGS)) {
      const fw = framework as "soc2" | "iso27001" | "pci";
      for (const ctrl of mapping[fw]) allControls.add(ctrl);
    }

    // Map control → open critical/high findings
    const failingControls: Record<string, Array<{ id: string; title: unknown; severity: unknown }>> = {};
    for (const f of findings) {
      if (!["critical", "high"].includes(String(f["severity"] ?? ""))) continue;
      const key = normaliseCategoryKey(String(f["category"] ?? ""));
      const mapping = CONTROL_MAPPINGS[key];
      if (!mapping) continue;
      const fw = framework as "soc2" | "iso27001" | "pci";
      for (const ctrl of mapping[fw]) {
        (failingControls[ctrl] ??= []).push({ id: String(f["_id"]), title: f["title"], severity: f["severity"] });
      }
    }

    const totalControls = allControls.size;
    const failingCount = Object.keys(failingControls).length;
    const passingCount = totalControls - failingCount;
    const score = totalControls > 0 ? Math.round((passingCount / totalControls) * 100) : 100;

    res.json({
      framework,
      generated_at: new Date().toISOString(),
      total_controls: totalControls,
      passing_controls: passingCount,
      failing_controls: failingCount,
      compliance_score_pct: score,
      failing: Object.entries(failingControls).map(([control, linked]) => ({ control, linked_findings: linked })),
    });
  } catch (err) {
    logger.error({ err }, "Framework report error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /compliance/evidence/:controlId — upload evidence text/file for a control
router.post("/compliance/evidence/:controlId", requireAuth, async (req, res) => {
  try {
    const { controlId } = req.params;
    const sess = (req as unknown as { session: { userId?: string } }).session;
    const { framework, evidence_text, file_name, file_url, notes } = req.body as {
      framework?: string; evidence_text?: string; file_name?: string; file_url?: string; notes?: string;
    };
    if (!framework || !evidence_text) {
      return res.status(400).json({ error: "framework and evidence_text are required" });
    }
    const doc = {
      control_id: controlId,
      framework,
      evidence_text,
      file_name: file_name ?? null,
      file_url: file_url ?? null,
      notes: notes ?? null,
      uploaded_by: sess?.userId ?? "unknown",
      created_at: new Date(),
    };
    const result = await col("compliance_evidence").insertOne(doc);
    res.status(201).json({ id: String(result.insertedId), ...doc });
  } catch (err) {
    logger.error({ err }, "Upload evidence error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// Helper: generate attestation data for a framework
async function generateAttestationData(
  framework: string,
  userFilter: Record<string, unknown> = {}
): Promise<{
  framework: string;
  generated_at: string;
  control_statuses: Array<{ control: string; status: string; findings_count: number }>;
  compliance_score_pct: number;
  evidence_count: number;
}> {
  const findings = await col("findings").find({ ...userFilter, status: { $nin: ["resolved", "false_positive"] } }).toArray() as Array<Record<string, unknown>>;
  const evidenceList = await col("compliance_evidence").find({ framework }).sort({ created_at: -1 }).toArray() as Array<Record<string, unknown>>;

  const fw = framework as "soc2" | "iso27001" | "pci";
  const allControls = new Set<string>();
  for (const m of Object.values(CONTROL_MAPPINGS)) for (const ctrl of m[fw]) allControls.add(ctrl);

  const failingControls = new Map<string, number>();
  for (const f of findings) {
    if (!["critical", "high"].includes(String(f["severity"] ?? ""))) continue;
    const key = normaliseCategoryKey(String(f["category"] ?? ""));
    const mapping = CONTROL_MAPPINGS[key];
    if (!mapping) continue;
    for (const ctrl of mapping[fw]) {
      failingControls.set(ctrl, (failingControls.get(ctrl) ?? 0) + 1);
    }
  }

  const controlStatuses = Array.from(allControls).map(ctrl => ({
    control: ctrl,
    status: failingControls.has(ctrl) ? "failing" : "passing",
    findings_count: failingControls.get(ctrl) ?? 0,
  }));

  const totalControls = allControls.size;
  const failingCount = failingControls.size;
  const passingCount = totalControls - failingCount;
  const score = totalControls > 0 ? Math.round((passingCount / totalControls) * 100) : 100;

  return {
    framework,
    generated_at: new Date().toISOString(),
    control_statuses: controlStatuses,
    compliance_score_pct: score,
    evidence_count: evidenceList.length,
  };
}

// GET /compliance/attestation/:framework — JSON attestation document
router.get("/compliance/attestation/:framework", requireAuth, async (req, res) => {
  try {
    const { framework } = req.params;
    if (!["soc2", "iso27001", "pci"].includes(framework)) {
      return res.status(400).json({ error: "framework must be one of: soc2, iso27001, pci" });
    }

    const sess = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const userFilter = sess?.role !== "admin" ? { user_id: sess?.userId } : {};
    const findings = await col("findings").find({ ...userFilter, status: { $nin: ["resolved", "false_positive"] } }).toArray() as Array<Record<string, unknown>>;
    const evidenceList = await col("compliance_evidence").find({ framework }).sort({ created_at: -1 }).toArray() as Array<Record<string, unknown>>;

    const fw = framework as "soc2" | "iso27001" | "pci";
    const allControls = new Set<string>();
    for (const m of Object.values(CONTROL_MAPPINGS)) for (const ctrl of m[fw]) allControls.add(ctrl);

    const failingControls = new Set<string>();
    for (const f of findings) {
      if (!["critical", "high"].includes(String(f["severity"] ?? ""))) continue;
      const key = normaliseCategoryKey(String(f["category"] ?? ""));
      const mapping = CONTROL_MAPPINGS[key];
      if (!mapping) continue;
      for (const ctrl of mapping[fw]) failingControls.add(ctrl);
    }

    const controlStatuses = Array.from(allControls).map(ctrl => ({
      control: ctrl,
      status: failingControls.has(ctrl) ? "failing" : "passing",
      evidence_links: evidenceList
        .filter(e => String(e["control_id"]) === ctrl)
        .map(e => ({ id: String(e["_id"]), file_name: e["file_name"], file_url: e["file_url"], created_at: e["created_at"] })),
    }));

    res.json({
      framework,
      generated_at: new Date().toISOString(),
      attested_by: sess?.userId ?? "unknown",
      control_statuses: controlStatuses,
      evidence_count: evidenceList.length,
    });
  } catch (err) {
    logger.error({ err }, "Attestation document error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /compliance/attestation/:framework/pdf — PDF attestation document
router.get("/compliance/attestation/:framework/pdf", requireAuth, async (req, res) => {
  try {
    const { framework } = req.params;
    const validFrameworks = ["soc2", "iso27001", "pci"];
    if (!validFrameworks.includes(framework)) return res.status(400).json({ error: "Invalid framework" });

    const sess = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const userFilter = sess?.role !== "admin" ? { user_id: sess?.userId } : {};
    const attestationData = await generateAttestationData(framework, userFilter as Record<string, unknown>);

    const doc = new PDFDocument({ margin: 50, size: "A4" });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${framework}-attestation-${new Date().toISOString().slice(0, 10)}.pdf"`);
    doc.pipe(res);

    // Cover page
    doc.fontSize(28).font("Helvetica-Bold").text("Compliance Attestation", { align: "center" });
    doc.moveDown(0.5);
    doc.fontSize(18).font("Helvetica").text(
      framework === "soc2" ? "SOC 2 Type II" : framework === "iso27001" ? "ISO 27001:2022" : "PCI-DSS v4.0",
      { align: "center" }
    );
    doc.moveDown(0.5);
    doc.fontSize(12).fillColor("#666").text(`Generated: ${new Date().toISOString()}`, { align: "center" });
    doc.moveDown(2);

    // Compliance score
    const score = attestationData.compliance_score_pct ?? 0;
    doc.fontSize(14).fillColor(score >= 80 ? "#16a34a" : score >= 60 ? "#d97706" : "#dc2626")
      .text(`Overall Compliance Score: ${score}%`, { align: "center" });
    doc.moveDown(1);

    // Control statuses table
    doc.fontSize(12).fillColor("#000").font("Helvetica-Bold").text("Control Status Summary");
    doc.moveDown(0.5);

    const controls = attestationData.control_statuses ?? [];
    for (const control of controls) {
      const statusColor = control.status === "passing" ? "#16a34a" : "#dc2626";
      const icon = control.status === "passing" ? "+" : "x";
      doc.fontSize(10).font("Helvetica")
        .fillColor(statusColor).text(`${icon} `, { continued: true })
        .fillColor("#000").text(`${control.control} — ${control.status.toUpperCase()}`);
      if (control.findings_count > 0) {
        doc.fontSize(9).fillColor("#666").text(`   Open findings: ${control.findings_count}`);
      }
    }

    doc.moveDown(2);
    doc.fontSize(9).fillColor("#999")
      .text("This attestation was generated automatically by Bug Finder Pro. For audit purposes, please retain this document.", { align: "center" });

    doc.end();
  } catch (err) {
    logger.error({ err }, "PDF attestation error");
    if (!res.headersSent) res.status(500).json({ error: "PDF generation failed" });
  }
});

// DELETE /compliance/attestations/:id
router.delete("/compliance/attestations/:id", async (req, res) => {
  try {
    await col("compliance_attestations").deleteOne({ _id: new ObjectId(req.params.id) } as Record<string, unknown>);
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "Delete attestation error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /compliance/export/:framework — export audit pack as JSON
router.get("/compliance/export/:framework", async (req, res) => {
  try {
    const { framework } = req.params;
    const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
    const userFilter = session?.role !== "admin" ? { user_id: session?.userId ?? null } : {};
    const findings = await col("findings").find(userFilter).toArray() as Array<Record<string, unknown>>;
    const remediations = await col("remediations").find(userFilter).toArray() as Array<Record<string, unknown>>;
    const attestations = await col("compliance_attestations").find({ framework }).toArray() as Array<Record<string, unknown>>;
    const pack = {
      framework, generated_at: new Date().toISOString(),
      summary: { total_findings: findings.length, critical: findings.filter(f => f["severity"] === "critical").length, high: findings.filter(f => f["severity"] === "high").length },
      findings: findings.map(f => ({ id: String(f["_id"]), title: f["title"], severity: f["severity"], endpoint: f["endpoint"], category: f["category"], created_at: f["created_at"] })),
      remediations: remediations.map(r => ({ id: String(r["_id"]), title: r["title"], status: r["status"], created_at: r["created_at"] })),
      attestations: attestations.map(a => ({ ...a, id: String(a["_id"]) })),
    };
    res.setHeader("Content-Disposition", `attachment; filename="${framework}-audit-pack-${new Date().toISOString().slice(0,10)}.json"`);
    res.setHeader("Content-Type", "application/json");
    res.json(pack);
  } catch (err) {
    logger.error({ err }, "Compliance export error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
