import { logger } from "../lib/logger";
import { col } from "../lib/db";

async function getSettingsOverrides(): Promise<Record<string, string>> {
  try {
    const s = (await col("settings").find().toArray())[0] as Record<string, unknown> | undefined;
    return {
      slack_webhook_url: String(s?.["slack_webhook_url"] ?? ""),
      teams_webhook_url: String(s?.["teams_webhook_url"] ?? ""),
      pagerduty_routing_key: String(s?.["pagerduty_routing_key"] ?? ""),
    };
  } catch { return {}; }
}

interface NotificationPayload {
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  message: string;
  targetUrl?: string;
  findingsCount?: number;
  riskScore?: number;
  scanId?: string;
  timestamp?: string;
}

export async function sendPagerDutyAlert(payload: NotificationPayload): Promise<boolean> {
  const overrides = await getSettingsOverrides();
  const routingKey = overrides["pagerduty_routing_key"] || process.env["PAGERDUTY_ROUTING_KEY"] || "";
  if (!routingKey) return false;

  const severity = payload.severity === "critical" ? "critical" : payload.severity === "high" ? "error" : "warning";
  try {
    const resp = await fetch("https://events.pagerduty.com/v2/enqueue", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        routing_key: routingKey,
        event_action: "trigger",
        payload: {
          summary: `[${payload.severity.toUpperCase()}] ${payload.title}`,
          severity,
          source: payload.targetUrl ?? "Bug Finder Pro",
          custom_details: { message: payload.message, risk_score: payload.riskScore, findings_count: payload.findingsCount },
        },
        dedup_key: `bugfinder-${payload.scanId ?? Date.now()}`,
      }),
    });
    if (resp.ok) { logger.info("PagerDuty alert sent"); return true; }
    return false;
  } catch (err) {
    logger.warn({ err }, "Failed to send PagerDuty alert");
    return false;
  }
}

export async function sendSlackNotification(payload: NotificationPayload): Promise<boolean> {
  const overrides = await getSettingsOverrides();
  const webhookUrl = overrides["slack_webhook_url"] || process.env["SLACK_WEBHOOK_URL"] || "";
  if (!webhookUrl) return false;

  const color = payload.severity === "critical" ? "#ef4444" :
                payload.severity === "high" ? "#f97316" :
                payload.severity === "medium" ? "#eab308" : "#22d3ee";

  try {
    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: `🚨 *Bug Finder Pro — ${payload.severity.toUpperCase()} Alert*`,
        attachments: [{
          color,
          title: payload.title,
          text: payload.message,
          fields: [
            { title: "Target", value: payload.targetUrl ?? "N/A", short: true },
            { title: "Findings", value: String(payload.findingsCount ?? 0), short: true },
            { title: "Risk Score", value: `${payload.riskScore ?? "N/A"}/100`, short: true },
            { title: "Time", value: new Date().toLocaleString(), short: true },
          ].filter(f => f.value !== "N/A"),
          footer: "Bug Finder Pro — Enterprise Security Platform",
          ts: Math.floor(Date.now() / 1000),
        }],
      }),
    });
    logger.info({ severity: payload.severity }, "Slack notification sent");
    return true;
  } catch (err) {
    logger.warn({ err }, "Failed to send Slack notification");
    return false;
  }
}

export async function sendTeamsNotification(payload: NotificationPayload): Promise<boolean> {
  const overrides = await getSettingsOverrides();
  const webhookUrl = overrides["teams_webhook_url"] || process.env["TEAMS_WEBHOOK_URL"] || "";
  if (!webhookUrl) return false;

  const color = payload.severity === "critical" ? "FF0000" :
                payload.severity === "high" ? "FF8C00" :
                payload.severity === "medium" ? "FFD700" : "00FF00";

  try {
    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        themeColor: color,
        summary: payload.title,
        title: `Bug Finder Pro — ${payload.severity.toUpperCase()}`,
        text: payload.message,
        sections: [{
          facts: [
            { name: "Target", value: payload.targetUrl ?? "N/A" },
            { name: "Findings", value: String(payload.findingsCount ?? 0) },
            { name: "Risk Score", value: `${payload.riskScore ?? "N/A"}/100` },
            { name: "Time", value: new Date().toLocaleString() },
          ],
        }],
      }),
    });
    logger.info({ severity: payload.severity }, "Teams notification sent");
    return true;
  } catch (err) {
    logger.warn({ err }, "Failed to send Teams notification");
    return false;
  }
}

export async function sendJiraTicket(payload: NotificationPayload & { description?: string }): Promise<boolean> {
  const jiraUrl = process.env["JIRA_URL"];
  const jiraEmail = process.env["JIRA_EMAIL"];
  const jiraToken = process.env["JIRA_API_TOKEN"];
  const jiraProject = process.env["JIRA_PROJECT"] ?? "SEC";

  if (!jiraUrl || !jiraEmail || !jiraToken) return false;

  try {
    const auth = Buffer.from(`${jiraEmail}:${jiraToken}`).toString("base64");
    const resp = await fetch(`${jiraUrl}/rest/api/3/issue`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Basic ${auth}`,
      },
      body: JSON.stringify({
        fields: {
          project: { key: jiraProject },
          summary: `[${payload.severity.toUpperCase()}] ${payload.title}`,
          description: {
            type: "doc",
            version: 1,
            content: [
              { type: "paragraph", content: [{ type: "text", text: payload.message }] },
              { type: "paragraph", content: [{ type: "text", text: `Target: ${payload.targetUrl ?? "N/A"}\nFindings: ${payload.findingsCount ?? 0}\nRisk Score: ${payload.riskScore ?? "N/A"}/100` }] },
              { type: "paragraph", content: [{ type: "text", text: payload.description ?? "" }] },
            ],
          },
          issuetype: { name: "Bug" },
          labels: ["security", payload.severity, "bug-finder-pro"],
        },
      }),
    });

    if (resp.ok) {
      const issue = await resp.json() as Record<string, unknown>;
      logger.info({ jiraKey: issue.key }, "Jira ticket created");
      return true;
    }
    return false;
  } catch (err) {
    logger.warn({ err }, "Failed to create Jira ticket");
    return false;
  }
}

export async function notifyAllChannels(payload: NotificationPayload & { description?: string }): Promise<void> {
  const results = await Promise.allSettled([
    sendSlackNotification(payload),
    sendTeamsNotification(payload),
    sendJiraTicket(payload),
    sendPagerDutyAlert(payload),
  ]);

  const successCount = results.filter(r => r.status === "fulfilled" && r.value).length;
  if (successCount === 0) {
    logger.warn("No notification channels configured — set SLACK_WEBHOOK_URL, TEAMS_WEBHOOK_URL, or JIRA_URL");
  }
}
