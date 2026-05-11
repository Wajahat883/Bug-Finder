import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";

const router = Router();

router.get("/reports/scan/:id/pdf", async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(404).json({ error: "Scan not found" });

    const scan = await col("scan_jobs").findOne({ _id: new ObjectId(id) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!scan) return res.status(404).json({ error: "Scan not found" });

    const findingsAll = await col("findings").find({ scan_job_id: new ObjectId(id) } as Record<string, unknown>).sort({ severity: 1 }).toArray() as Array<Record<string, unknown>>;

    const findings = findingsAll.map((f) => ({
      title: String(f["title"] ?? ""),
      severity: String(f["severity"] ?? ""),
      category: String(f["category"] ?? ""),
      endpoint: String(f["endpoint"] ?? ""),
      cvss_score: f["cvss_score"] ?? 0,
      cwe_id: f["cwe_id"] ?? "N/A",
      description: String(f["description"] ?? "").slice(0, 300),
      recommended_fix: String(f["recommended_fix"] ?? "").slice(0, 200),
    }));

    const now = new Date().toISOString().slice(0, 10);
    const riskScore = (scan["risk_score"] as number) ?? 0;
    const riskLabel = riskScore > 80 ? "CRITICAL" : riskScore > 60 ? "HIGH" : riskScore > 30 ? "MEDIUM" : "LOW";
    const critCount = (scan["critical_count"] as number) ?? 0;
    const highCount = (scan["high_count"] as number) ?? 0;
    const medCount = (scan["medium_count"] as number) ?? 0;
    const lowCount = (scan["low_count"] as number) ?? 0;

    const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Security Scan Report</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family: 'Inter', Arial, sans-serif; color: #1a1a2e; font-size: 12px; line-height: 1.5; }
  .cover { padding: 60px 40px; text-align: center; background: linear-gradient(135deg, #0a0a0f, #1a1a2e); color: white; min-height: 500px; }
  .cover h1 { font-size: 36px; margin-bottom: 12px; color: #a78bfa; }
  .cover .target { font-size: 18px; color: #22d3ee; font-family: monospace; margin-bottom: 8px; }
  .cover .date { font-size: 14px; color: #6b6b80; margin-bottom: 40px; }
  .cover .score { font-size: 72px; font-weight: 900; margin: 20px 0; }
  .cover .risk-label { font-size: 20px; text-transform: uppercase; letter-spacing: 4px; }
  .summary { padding: 30px 40px; border-bottom: 1px solid #e4e4e7; }
  .summary h2 { font-size: 20px; margin-bottom: 12px; color: #7c3aed; }
  .summary-grid { display: flex; gap: 20px; margin: 16px 0; }
  .summary-card { flex:1; padding: 16px; border-radius: 8px; text-align: center; }
  .summary-card.critical { background: #fef2f2; border: 1px solid #fecaca; }
  .summary-card.high { background: #fffbeb; border: 1px solid #fde68a; }
  .summary-card.medium { background: #fefce8; border: 1px solid #fef08a; }
  .summary-card.low { background: #f0fdf4; border: 1px solid #bbf7d0; }
  .summary-card .count { font-size: 28px; font-weight: 700; }
  .summary-card .label { font-size: 11px; color: #6b7280; margin-top: 4px; }
  .findings { padding: 20px 40px; }
  .findings h2 { font-size: 20px; margin-bottom: 16px; color: #7c3aed; }
  .finding { padding: 14px; margin-bottom: 8px; border: 1px solid #e4e4e7; border-radius: 8px; border-left: 4px solid #7c3aed; page-break-inside: avoid; }
  .finding.crit { border-left-color: #ef4444; }
  .finding.high { border-left-color: #f97316; }
  .finding.med { border-left-color: #eab308; }
  .finding.low { border-left-color: #22d3ee; }
  .finding .sev { font-size: 10px; font-weight: 700; text-transform: uppercase; margin-bottom: 4px; }
  .finding .sev.crit { color: #ef4444; }
  .finding .sev.high { color: #f97316; }
  .finding .sev.med { color: #eab308; }
  .finding .sev.low { color: #22d3ee; }
  .finding h3 { font-size: 14px; margin-bottom: 4px; }
  .finding .meta { font-size: 10px; color: #6b7280; margin-bottom: 6px; }
  .finding .desc { font-size: 11px; color: #374151; margin-bottom: 4px; }
  .finding .fix { font-size: 10px; color: #059669; font-family: monospace; background: #ecfdf5; padding: 4px 6px; border-radius: 4px; }
  .footer { padding: 16px 40px; text-align: center; font-size: 10px; color: #9ca3af; border-top: 1px solid #e4e4e7; }
</style></head><body>
<div class="cover">
  <h1>Bug Finder Pro</h1>
  <h2 style="font-weight:400;color:#e8e8ef;margin-bottom:24px;">Security Assessment Report</h2>
  <div class="target">${scan["target_url"]}</div>
  <div class="date">${new Date(scan["created_at"] as string).toLocaleDateString("en-US", {year:"numeric",month:"long",day:"numeric"})} — ${now}</div>
  <div class="score" style="color:${riskScore>80?'#ef4444':riskScore>60?'#f97316':riskScore>30?'#eab308':'#22d3ee'}">${riskScore}</div>
  <div class="risk-label" style="color:${riskScore>80?'#ef4444':riskScore>60?'#f97316':riskScore>30?'#eab308':'#22d3ee'}">Risk Score: ${riskLabel}</div>
  <p style="color:#6b6b80;margin-top:16px;">Scan Profile: ${scan["scan_profile"] ?? "standard"} | Scanned on ${new Date(scan["created_at"] as string).toLocaleDateString()}</p>
</div>
<div class="summary">
  <h2>Executive Summary</h2>
  <p style="margin-bottom:12px;">This scan identified ${findings.length} security vulnerabilities across ${scan["target_url"]}. The overall risk posture is <strong>${riskLabel}</strong>.</p>
  <div class="summary-grid">
    <div class="summary-card critical"><div class="count">${critCount}</div><div class="label">Critical</div></div>
    <div class="summary-card high"><div class="count">${highCount}</div><div class="label">High</div></div>
    <div class="summary-card medium"><div class="count">${medCount}</div><div class="label">Medium</div></div>
    <div class="summary-card low"><div class="count">${lowCount}</div><div class="label">Low</div></div>
  </div>
  <p style="font-size:11px;color:#6b7280;">${critCount > 0 ? `⚠ Immediate action required: ${critCount} critical findings must be addressed within 24 hours.` : ""} ${highCount > 0 ? `${highCount} high-severity findings require attention within 72 hours.` : ""} ${critCount === 0 && highCount === 0 ? "No critical or high findings detected." : ""}</p>
</div>
<div class="findings">
  <h2>Detailed Findings</h2>
  ${findings.map((f, i) => `
  <div class="finding ${f.severity.slice(0,4)}">
    <div class="sev ${f.severity.slice(0,4)}">${f.severity}</div>
    <h3>${i + 1}. ${f.title}</h3>
    <div class="meta">${f.endpoint} | CVSS: ${f.cvss_score} | CWE: ${f.cwe_id} | ${f.category}</div>
    <div class="desc">${f.description || "No description provided."}</div>
    ${f.recommended_fix ? `<div class="fix">Fix: ${f.recommended_fix}</div>` : ""}
  </div>`).join("\n")}
  ${findings.length === 0 ? '<p style="color:#6b7280;">No vulnerabilities found.</p>' : ""}
</div>
<div class="footer">
  <p>Bug Finder Pro — Security Assessment Report | Generated on ${now} | Confidential</p>
  <p>This report is for authorized security testing purposes only.</p>
</div>
</body></html>`;

    res.setHeader("Content-Type", "text/html");
    res.setHeader("Content-Disposition", `attachment; filename="scan-report-${id.slice(0, 8)}-${now}.html"`);
    res.send(html);
  } catch (err) {
    logger.error({ err }, "PDF generation error");
    res.status(500).json({ error: "Report generation failed" });
  }
});

export default router;
