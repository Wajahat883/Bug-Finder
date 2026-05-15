import { Router } from "express";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAdmin } from "../middlewares/rbac";

const router = Router();

export const SLA_DAYS: Record<string, number> = {
  critical: 1,
  high: 7,
  medium: 30,
  low: 90,
};

router.post("/sla/enforce", requireAdmin, async (_req, res) => {
  try {
    const now = new Date();
    const breached: Array<Record<string, unknown>> = [];

    for (const [severity, days] of Object.entries(SLA_DAYS)) {
      const deadline = new Date(now.getTime() - days * 86400000);
      const findings = await col("findings").find({
        severity,
        status: { $nin: ["resolved", "false_positive"] },
        triage_status: { $nin: ["accepted", "suppressed"] },
        created_at: { $lte: deadline },
        sla_notified: { $ne: true },
      } as Record<string, unknown>).limit(100).toArray() as Array<Record<string, unknown>>;

      for (const finding of findings) {
        breached.push(finding);
        await col("findings").updateOne(
          { _id: finding["_id"] } as Record<string, unknown>,
          { $set: { sla_notified: true, sla_breached_at: now } }
        );
      }
    }

    if (breached.length > 0) {
      try {
        const settings = await col("settings").find({}).limit(1).toArray() as Array<Record<string, unknown>>;
        const slackUrl = String(settings[0]?.["slack_webhook_url"] ?? "") || process.env["SLACK_WEBHOOK_URL"] || "";
        if (slackUrl) {
          await fetch(slackUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              text: `:alarm_clock: *SLA Breach Alert* — ${breached.length} finding(s) breached their SLA deadline.`,
              blocks: [
                { type: "header", text: { type: "plain_text", text: "⏰ SLA Breach Alert" } },
                { type: "section", text: { type: "mrkdwn", text: `*${breached.length} finding(s)* have exceeded their SLA deadline.` } },
                ...breached.slice(0, 5).map(f => ({
                  type: "section",
                  text: { type: "mrkdwn", text: `• *[${String(f["severity"] ?? "").toUpperCase()}]* ${String(f["title"] ?? "Untitled")} — \`${String(f["endpoint"] ?? "")}\`` },
                })),
              ],
            }),
          });
        }
      } catch (slackErr) {
        logger.warn({ err: slackErr }, "SLA Slack notification failed");
      }

      try {
        const { sendEmail } = await import("../services/email");
        const adminEmail = process.env["ADMIN_EMAIL"] ?? "";
        if (adminEmail) {
          const rows = breached.slice(0, 20).map(f =>
            `<tr><td>${String(f["severity"] ?? "").toUpperCase()}</td><td>${String(f["title"] ?? "")}</td><td>${String(f["endpoint"] ?? "")}</td></tr>`
          ).join("");
          await sendEmail({
            to: adminEmail,
            subject: `[SLA Alert] ${breached.length} finding(s) breached SLA`,
            html: `<h2>SLA Breach Report</h2><p>${breached.length} finding(s) exceeded their SLA deadline.</p><table border="1" cellpadding="4"><tr><th>Severity</th><th>Title</th><th>Endpoint</th></tr>${rows}</table>`,
          });
        }
      } catch (emailErr) {
        logger.warn({ err: emailErr }, "SLA email failed");
      }
    }

    res.json({ ok: true, breached_count: breached.length, findings: breached.map(f => ({ id: String(f["_id"]), title: f["title"], severity: f["severity"] })) });
  } catch (err) {
    logger.error({ err }, "SLA enforcement error");
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/sla/report", requireAdmin, async (_req, res) => {
  try {
    const now = new Date();
    const report: Record<string, { total: number; breached: number; at_risk: number; compliant: number }> = {};

    for (const [severity, days] of Object.entries(SLA_DAYS)) {
      const deadline = new Date(now.getTime() - days * 86400000);
      const atRiskDeadline = new Date(now.getTime() - days * 0.8 * 86400000);
      const [total, breached, atRisk] = await Promise.all([
        col("findings").countDocuments({ severity, status: { $nin: ["resolved"] } } as Record<string, unknown>),
        col("findings").countDocuments({ severity, status: { $nin: ["resolved"] }, created_at: { $lte: deadline } } as Record<string, unknown>),
        col("findings").countDocuments({ severity, status: { $nin: ["resolved"] }, created_at: { $lte: atRiskDeadline, $gt: deadline } } as Record<string, unknown>),
      ]);
      report[severity] = { total, breached, at_risk: atRisk, compliant: total - breached - atRisk };
    }

    res.json({ report, sla_days: SLA_DAYS, generated_at: now });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
