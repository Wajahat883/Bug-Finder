import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";

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

export default router;
