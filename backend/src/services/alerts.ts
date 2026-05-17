import { col } from "../lib/db";
import { logger } from "../lib/logger";

export async function sendIntegrationAlerts(finding: Record<string, unknown>): Promise<void> {
  const settings = await col("settings").findOne({}) as Record<string, unknown> | null;

  // Slack alert
  const slackUrl = settings?.["slack_webhook_url"] as string;
  if (slackUrl) {
    const payload = {
      text: `🚨 *${String(finding["severity"]).toUpperCase()} Finding*: ${finding["title"]}`,
      attachments: [{
        color: finding["severity"] === "critical" ? "danger" : "warning",
        fields: [
          { title: "Endpoint", value: String(finding["endpoint"] ?? "Unknown"), short: true },
          { title: "CVSS", value: String(finding["cvss_score"] ?? "N/A"), short: true },
          { title: "Status", value: String(finding["status"] ?? "open"), short: true },
        ],
        footer: "Bug Finder Pro",
        ts: Math.floor(Date.now() / 1000),
      }]
    };
    await fetch(slackUrl, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }).catch(() => {});
  }

  // Teams alert
  const teamsUrl = settings?.["teams_webhook_url"] as string;
  if (teamsUrl) {
    const payload = {
      "@type": "MessageCard",
      "@context": "http://schema.org/extensions",
      themeColor: finding["severity"] === "critical" ? "FF0000" : "FFA500",
      summary: `${finding["severity"]?.toString().toUpperCase()} Finding: ${finding["title"]}`,
      sections: [{
        activityTitle: `🚨 ${finding["severity"]?.toString().toUpperCase()}: ${finding["title"]}`,
        facts: [
          { name: "Endpoint", value: String(finding["endpoint"] ?? "Unknown") },
          { name: "CVSS Score", value: String(finding["cvss_score"] ?? "N/A") },
        ]
      }]
    };
    await fetch(teamsUrl, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }).catch(() => {});
  }
}
