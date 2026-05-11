import nodemailer from "nodemailer";
import { logger } from "../lib/logger";

function createTransport() {
  const host = process.env["SMTP_HOST"];
  if (!host) return null;

  return nodemailer.createTransport({
    host,
    port: parseInt(process.env["SMTP_PORT"] ?? "587"),
    secure: false,
    auth: process.env["SMTP_USER"]
      ? { user: process.env["SMTP_USER"], pass: process.env["SMTP_PASS"] }
      : undefined,
  });
}

export interface ReportData {
  title: string;
  generatedAt: Date;
  targetUrl?: string;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  topFindings: Array<{ title: string; severity: string; endpoint: string }>;
  openRemediations: number;
  resolvedLastPeriod: number;
}

export async function sendReportEmail(to: string | string[], report: ReportData): Promise<boolean> {
  const transport = createTransport();
  if (!transport) {
    logger.warn("SMTP not configured — report email not sent");
    return false;
  }

  const toAddr = Array.isArray(to) ? to.join(", ") : to;
  const sevBadge = (s: string, n: number) => {
    const colors: Record<string, string> = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22d3ee" };
    const c = colors[s] ?? "#6b7280";
    return `<span style="display:inline-block;padding:2px 8px;border-radius:4px;background:${c}22;color:${c};font-weight:700;font-size:12px;">${s.toUpperCase()}: ${n}</span>`;
  };

  const findingRows = report.topFindings.slice(0, 10).map((f) => {
    const c = ({ critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22d3ee" }[f.severity] ?? "#6b7280");
    return `<tr><td style="padding:6px 8px;border-bottom:1px solid #333;">${f.title}</td>
      <td style="padding:6px 8px;border-bottom:1px solid #333;"><span style="color:${c};font-weight:600;">${f.severity.toUpperCase()}</span></td>
      <td style="padding:6px 8px;border-bottom:1px solid #333;font-family:monospace;font-size:11px;">${f.endpoint}</td></tr>`;
  }).join("");

  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0f0e17;font-family:Inter,sans-serif;color:#e8e6f0;">
  <div style="max-width:680px;margin:32px auto;background:#16151f;border-radius:12px;overflow:hidden;border:1px solid #2a2840;">
    <div style="background:linear-gradient(135deg,#6d28d9,#4f46e5);padding:28px 32px;">
      <h1 style="margin:0;font-size:22px;color:#fff;">🛡️ ${report.title}</h1>
      <p style="margin:6px 0 0;color:rgba(255,255,255,.7);font-size:13px;">
        Generated ${report.generatedAt.toUTCString()}${report.targetUrl ? ` · ${report.targetUrl}` : ""}
      </p>
    </div>
    <div style="padding:28px 32px;">
      <h2 style="margin:0 0 16px;font-size:15px;color:#a89fd4;text-transform:uppercase;letter-spacing:.08em;">Summary</h2>
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:24px;">
        ${sevBadge("critical", report.critical)}
        ${sevBadge("high", report.high)}
        ${sevBadge("medium", report.medium)}
        ${sevBadge("low", report.low)}
        <span style="display:inline-block;padding:2px 8px;border-radius:4px;background:#6b728022;color:#aaa;font-weight:700;font-size:12px;">TOTAL: ${report.totalFindings}</span>
      </div>
      <div style="display:flex;gap:20px;margin-bottom:28px;">
        <div style="background:#1e1c2e;border-radius:8px;padding:14px 20px;flex:1;text-align:center;">
          <div style="font-size:28px;font-weight:700;color:#ef4444;">${report.openRemediations}</div>
          <div style="font-size:12px;color:#888;margin-top:4px;">Open Remediations</div>
        </div>
        <div style="background:#1e1c2e;border-radius:8px;padding:14px 20px;flex:1;text-align:center;">
          <div style="font-size:28px;font-weight:700;color:#22c55e;">${report.resolvedLastPeriod}</div>
          <div style="font-size:12px;color:#888;margin-top:4px;">Resolved This Period</div>
        </div>
      </div>
      ${findingRows ? `
      <h2 style="margin:0 0 12px;font-size:15px;color:#a89fd4;text-transform:uppercase;letter-spacing:.08em;">Top Findings</h2>
      <table style="width:100%;border-collapse:collapse;font-size:13px;">
        <thead><tr style="color:#888;">
          <th style="text-align:left;padding:6px 8px;border-bottom:1px solid #2a2840;">Title</th>
          <th style="text-align:left;padding:6px 8px;border-bottom:1px solid #2a2840;">Severity</th>
          <th style="text-align:left;padding:6px 8px;border-bottom:1px solid #2a2840;">Endpoint</th>
        </tr></thead>
        <tbody>${findingRows}</tbody>
      </table>` : ""}
    </div>
    <div style="padding:16px 32px;border-top:1px solid #2a2840;font-size:11px;color:#555;text-align:center;">
      Bug Finder Pro · Automated Security Report
    </div>
  </div>
</body></html>`;

  try {
    await transport.sendMail({
      from: process.env["SMTP_FROM"] ?? "noreply@bugfinder.io",
      to: toAddr,
      subject: `[Bug Finder Pro] ${report.title}`,
      html,
      text: `${report.title}\n\nCritical: ${report.critical} | High: ${report.high} | Medium: ${report.medium} | Low: ${report.low}\nTotal: ${report.totalFindings} findings\nOpen remediations: ${report.openRemediations}`,
    });
    return true;
  } catch (err) {
    logger.error({ err }, "Failed to send report email");
    return false;
  }
}

export async function sendEmail(opts: { to: string; subject: string; html: string; text?: string }): Promise<boolean> {
  const transport = createTransport();
  if (!transport) return false;
  try {
    await transport.sendMail({
      from: process.env["SMTP_FROM"] ?? "noreply@bugfinder.io",
      to: opts.to,
      subject: opts.subject,
      html: opts.html,
      text: opts.text ?? opts.html.replace(/<[^>]*>/g, ""),
    });
    return true;
  } catch (err) {
    logger.error({ err }, "Failed to send email");
    return false;
  }
}

export async function sendPasswordResetEmail(to: string, token: string, baseUrl = "http://localhost:3000"): Promise<boolean> {
  const transport = createTransport();
  if (!transport) {
    logger.warn("SMTP not configured — password reset email not sent");
    return false;
  }

  const resetUrl = `${baseUrl}/reset-password?token=${token}`;
  try {
    await transport.sendMail({
      from: process.env["SMTP_FROM"] ?? "noreply@bugfinder.io",
      to,
      subject: "Bug Finder Pro — Password Reset",
      html: `
        <h2>Password Reset Request</h2>
        <p>Click the link below to reset your password. This link expires in 1 hour.</p>
        <p><a href="${resetUrl}" style="background:#6d28d9;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;">Reset Password</a></p>
        <p>If you did not request this, ignore this email.</p>
      `,
      text: `Reset your password: ${resetUrl}`,
    });
    return true;
  } catch (err) {
    logger.error({ err }, "Failed to send password reset email");
    return false;
  }
}
