import { logger } from "../lib/logger";

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

export async function sendSlackNotification(payload: NotificationPayload): Promise<boolean> {
  const webhookUrl = process.env["SLACK_WEBHOOK_URL"];
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
  const webhookUrl = process.env["TEAMS_WEBHOOK_URL"];
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
  ]);

  const successCount = results.filter(r => r.status === "fulfilled" && r.value).length;
  if (successCount === 0) {
    logger.warn("No notification channels configured — set SLACK_WEBHOOK_URL, TEAMS_WEBHOOK_URL, or JIRA_URL");
  }
}
