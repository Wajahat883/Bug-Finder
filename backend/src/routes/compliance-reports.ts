import { Router } from "express";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";

const router = Router();

interface ComplianceFramework {
  id: string;
  name: string;
  controls: Array<{ id: string; title: string; description: string; findingCategories: string[] }>;
}

const PCI_DSS: ComplianceFramework = {
  id: "pci-dss",
  name: "PCI DSS 4.0",
  controls: [
    { id: "6.1", title: "Install Security Patches", description: "Ensure all system components and software are protected from known vulnerabilities", findingCategories: ["Injection", "Security Misconfiguration", "CVE"] },
    { id: "6.2", title: "Secure Coding Practices", description: "Develop applications based on secure coding guidelines", findingCategories: ["Cross-Site Scripting", "SQL Injection", "Injection", "Path Traversal"] },
    { id: "6.3", title: "Vulnerability Assessment", description: "Identify and rank vulnerabilities based on risk", findingCategories: ["*"] },
    { id: "6.4", title: "Change Control", description: "Follow change control procedures for all changes", findingCategories: ["Security Misconfiguration"] },
    { id: "6.5", title: "Code Review", description: "Review code to identify potential coding vulnerabilities", findingCategories: ["*"] },
    { id: "7.1", title: "Access Control", description: "Limit access to system components based on need to know", findingCategories: ["Authentication", "Broken Access Control", "JWT Security", "CORS"] },
    { id: "8.1", title: "Authentication Mechanisms", description: "Implement strong authentication for all users", findingCategories: ["Authentication", "JWT Security", "OAuth"] },
    { id: "8.2", title: "Password Policies", description: "Enforce strong password policies", findingCategories: ["Authentication"] },
    { id: "10.1", title: "Audit Logging", description: "Implement automated audit trails", findingCategories: ["Security Misconfiguration"] },
    { id: "11.1", title: "Wireless Security", description: "Use and regularly update wireless security measures", findingCategories: ["TLS", "Network Security"] },
  ],
};

const SOC2: ComplianceFramework = {
  id: "soc2",
  name: "SOC 2 Type II",
  controls: [
    { id: "CC6.1", title: "Logical & Physical Access Controls", description: "Controls to restrict logical access to system resources", findingCategories: ["Authentication", "Broken Access Control", "CORS"] },
    { id: "CC6.2", title: "User Access Provisioning", description: "Controls for granting and revoking user access", findingCategories: ["Authentication", "JWT Security"] },
    { id: "CC6.3", title: "Security Awareness", description: "Personnel security awareness and training", findingCategories: ["Security Misconfiguration"] },
    { id: "CC7.1", title: "Vulnerability Detection", description: "Detect vulnerabilities through ongoing monitoring", findingCategories: ["*"] },
    { id: "CC7.2", title: "Security Incident Response", description: "Respond to security incidents", findingCategories: ["*"] },
    { id: "CC7.3", title: "Vulnerability Remediation", description: "Remediate identified vulnerabilities", findingCategories: ["*"] },
    { id: "CC8.1", title: "Change Management", description: "Manage changes to prevent security issues", findingCategories: ["Security Misconfiguration"] },
  ],
};

const HIPAA: ComplianceFramework = {
  id: "hipaa",
  name: "HIPAA Security Rule",
  controls: [
    { id: "164.308(a)(1)", title: "Security Management Process", description: "Risk analysis and management", findingCategories: ["*"] },
    { id: "164.308(a)(3)", title: "Workforce Security", description: "Authorization and supervision of workforce", findingCategories: ["Authentication", "Broken Access Control"] },
    { id: "164.308(a)(4)", title: "Information Access Management", description: "Access authorization and establishment", findingCategories: ["Authentication", "Broken Access Control", "CORS", "JWT Security"] },
    { id: "164.308(a)(5)", title: "Security Awareness Training", description: "Security reminders and training", findingCategories: ["Security Misconfiguration"] },
    { id: "164.312(a)(1)", title: "Access Control", description: "Unique user identification and automatic logoff", findingCategories: ["Authentication", "JWT Security"] },
    { id: "164.312(b)", title: "Audit Controls", description: "Record and examine system activity", findingCategories: ["Security Misconfiguration"] },
    { id: "164.312(e)(1)", title: "Transmission Security", description: "Protect electronic PHI during transmission", findingCategories: ["TLS", "Security Headers"] },
  ],
};

const ISO27001: ComplianceFramework = {
  id: "iso27001",
  name: "ISO 27001:2022",
  controls: [
    { id: "A.8.8", title: "Technical Vulnerability Management", description: "Identify and manage technical vulnerabilities", findingCategories: ["*"] },
    { id: "A.8.9", title: "Configuration Management", description: "Establish and maintain secure configurations", findingCategories: ["Security Misconfiguration", "Security Headers", "TLS"] },
    { id: "A.8.20", title: "Network Security", description: "Secure networks and network services", findingCategories: ["Network Security", "TLS", "DNS"] },
    { id: "A.8.25", title: "Secure Development Lifecycle", description: "Apply secure development practices", findingCategories: ["Injection", "Cross-Site Scripting", "File Upload"] },
    { id: "A.5.15", title: "Access Control", description: "Control access to information and assets", findingCategories: ["Authentication", "Broken Access Control", "CORS"] },
    { id: "A.5.17", title: "Authentication Information", description: "Manage authentication information securely", findingCategories: ["Authentication", "JWT Security"] },
    { id: "A.8.15", title: "Logging", description: "Record events and generate evidence", findingCategories: ["Security Misconfiguration"] },
  ],
};

const FRAMEWORKS: ComplianceFramework[] = [PCI_DSS, SOC2, HIPAA, ISO27001];

function getControlStatus(categories: string[], controlCategories: string[]): "pass" | "fail" | "untested" {
  if (controlCategories.includes("*")) {
    return categories.length > 0 ? "fail" : "pass";
  }
  const relevant = categories.filter(cat =>
    controlCategories.some(ctrl => cat.toLowerCase().includes(ctrl.toLowerCase()) ||
      ctrl.toLowerCase().includes(cat.toLowerCase()))
  );
  return relevant.length > 0 ? "fail" : "untested";
}

// GET /compliance/report/:framework — Generate compliance report
router.get("/compliance/report/:framework", requireAuth, async (req, res) => {
  try {
    const framework = FRAMEWORKS.find(f => f.id === req.params.framework);
    if (!framework) {
      return res.status(404).json({ error: "Framework not found" });
    }

    const findings = await col("findings").find({ validation_status: { $ne: "false_positive" } }).toArray() as Array<Record<string, unknown>>;
    const allCategories = [...new Set(findings.map(f => String(f["category"] ?? "")))];

    const controls = framework.controls.map(ctrl => {
      const relevantFindings = findings.filter(f => {
        const cat = String(f["category"] ?? "");
        if (ctrl.findingCategories.includes("*")) return true;
        return ctrl.findingCategories.some(fc => cat.toLowerCase().includes(fc.toLowerCase()));
      });

      return {
        id: ctrl.id,
        title: ctrl.title,
        description: ctrl.description,
        status: getControlStatus(allCategories, ctrl.findingCategories),
        findingCount: relevantFindings.length,
        criticalCount: relevantFindings.filter(f => f["severity"] === "critical").length,
        highCount: relevantFindings.filter(f => f["severity"] === "high").length,
      };
    });

    const totalControls = controls.length;
    const passedControls = controls.filter(c => c.status === "pass").length;
    const failedControls = controls.filter(c => c.status === "fail").length;
    const untestedControls = controls.filter(c => c.status === "untested").length;
    const complianceScore = totalControls > 0 ? Math.round((passedControls / totalControls) * 100) : 100;

    const html = generateComplianceHtml(framework, controls, complianceScore, totalControls, passedControls, failedControls, untestedControls);
    res.setHeader("Content-Type", "text/html");
    res.setHeader("Content-Disposition", `attachment; filename="${framework.id}-compliance-report.html"`);
    res.send(html);
  } catch (err) {
    logger.error({ err }, "Compliance report error");
    res.status(500).json({ error: "Report generation failed" });
  }
});

function generateComplianceHtml(
  framework: ComplianceFramework,
  controls: Array<{ id: string; title: string; description: string; status: string; findingCount: number; criticalCount: number; highCount: number }>,
  score: number, total: number, passed: number, failed: number, untested: number
): string {
  const rows = controls.map(c => `
    <tr>
      <td style="padding:8px 12px;border-bottom:1px solid #e4e4e7;font-family:monospace;font-size:12px">${c.id}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #e4e4e7;font-size:12px"><strong>${c.title}</strong><br><span style="color:#6b7280">${c.description}</span></td>
      <td style="padding:8px 12px;border-bottom:1px solid #e4e4e7;text-align:center">
        <span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;color:white;background:${c.status === 'pass' ? '#22c55e' : c.status === 'fail' ? '#ef4444' : '#9ca3af'}">${c.status.toUpperCase()}</span>
      </td>
      <td style="padding:8px 12px;border-bottom:1px solid #e4e4e7;text-align:center;font-size:12px">${c.findingCount > 0 ? `<span style="color:#ef4444">${c.findingCount}</span>` : '0'}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #e4e4e7;text-align:center;font-size:12px;color:#ef4444">${c.criticalCount || '-'}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #e4e4e7;text-align:center;font-size:12px;color:#f97316">${c.highCount || '-'}</td>
    </tr>
  `).join("");

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>${framework.name} Compliance Report</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}body{font-family:Inter,Arial,sans-serif;color:#1a1a2e;font-size:12px;line-height:1.6}
  .header{padding:40px 50px;background:linear-gradient(135deg,#0a0a0f,#1a1a2e);color:white}
  .header h1{font-size:28px;margin-bottom:4px}.header .sub{color:#a78bfa;font-size:14px}
  .summary{padding:24px 50px;display:flex;gap:20px;border-bottom:1px solid #e4e4e7}
  .score-box{width:120px;height:120px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:32px;font-weight:900}
  .content{padding:30px 50px}table{width:100%;border-collapse:collapse}th{text-align:left;padding:8px 12px;font-size:11px;text-transform:uppercase;color:#6b7280;border-bottom:2px solid #e4e4e7}
  .footer{padding:16px 50px;text-align:center;font-size:10px;color:#9ca3af;border-top:1px solid #e4e4e7}
</style></head><body>
<div class="header">
  <h1>${framework.name} Compliance Report</h1>
  <p class="sub">Generated by Bug Finder Pro — ${new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}</p>
</div>
<div class="summary">
  <div class="score-box" style="background:${score >= 80 ? '#22c55e15' : score >= 50 ? '#f9731615' : '#ef444415'};color:${score >= 80 ? '#22c55e' : score >= 50 ? '#f97316' : '#ef4444'}">${score}%</div>
  <div style="flex:1;display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px">
    <div><div style="font-size:24px;font-weight:700;color:#22c55e">${passed}</div><div style="font-size:11px;color:#6b7280">PASSED</div></div>
    <div><div style="font-size:24px;font-weight:700;color:#ef4444">${failed}</div><div style="font-size:11px;color:#6b7280">FAILED</div></div>
    <div><div style="font-size:24px;font-weight:700;color:#9ca3af">${untested}</div><div style="font-size:11px;color:#6b7280">UNTESTED</div></div>
  </div>
</div>
<div class="content">
  <table><thead><tr><th>Control ID</th><th>Description</th><th style="text-align:center">Status</th><th style="text-align:center">Findings</th><th style="text-align:center">Critical</th><th style="text-align:center">High</th></tr></thead><tbody>${rows}</tbody></table>
</div>
<div class="footer"><p>Bug Finder Pro — Enterprise Security Platform | ${framework.name} Compliance Report | Confidential</p><p>This report is generated automatically based on current scan findings. Auditor verification recommended.</p></div>
</body></html>`;
}

// GET /compliance/frameworks — List available frameworks
router.get("/compliance/frameworks", requireAuth, (_req, res) => {
  res.json(FRAMEWORKS.map(f => ({
    id: f.id,
    name: f.name,
    controlCount: f.controls.length,
  })));
});

export default router;
