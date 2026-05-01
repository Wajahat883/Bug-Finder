import { Router } from "express";
import { ObjectId } from "mongodb";
import { anthropic } from "@workspace/integrations-anthropic-ai";
import { col } from "../lib/db";
import { logger } from "../lib/logger";

const router = Router();

router.post("/ai/scan-summary/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const scan = await col("scan_jobs").findOne({ _id: new ObjectId(id) } as Record<string, unknown>);
    if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }

    const findings = await col("findings").find({ scan_job_id: new ObjectId(id) } as Record<string, unknown>).toArray();

    const criticals = findings.filter((f: Record<string, unknown>) => f.severity === "critical");
    const highs = findings.filter((f: Record<string, unknown>) => f.severity === "high");
    const mediums = findings.filter((f: Record<string, unknown>) => f.severity === "medium");

    const topFindings = [...criticals, ...highs].slice(0, 8).map((f: Record<string, unknown>) =>
      `- [${String(f.severity).toUpperCase()}] ${f.title} — ${f.endpoint} (CVSS: ${f.cvss_score ?? "N/A"}, CWE: ${f.cwe_id ?? "N/A"})`
    ).join("\n");

    const prompt = `You are a senior penetration tester writing a brief security assessment summary for a client report.

Target: ${scan.target_url}
Scan Profile: ${scan.profile}
Risk Score: ${scan.risk_score}/100
Total Findings: ${findings.length} (Critical: ${criticals.length}, High: ${highs.length}, Medium: ${mediums.length})

Top findings:
${topFindings || "No critical/high findings."}

Write a concise 3-paragraph executive summary:
1. Overall security posture and risk level (2-3 sentences)
2. Most critical issues and their business impact (3-4 sentences covering the top vulnerabilities)
3. Immediate recommended actions (2-3 prioritized steps)

Use professional language appropriate for a security report. Be specific about the vulnerabilities found. Do not use markdown headers or bullet points — write in flowing paragraphs.`;

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");

    const stream = anthropic.messages.stream({
      model: "claude-sonnet-4-6",
      max_tokens: 8192,
      messages: [{ role: "user", content: prompt }],
    });

    for await (const event of stream) {
      if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
        res.write(`data: ${JSON.stringify({ content: event.delta.text })}\n\n`);
      }
    }

    res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
    res.end();
  } catch (err) {
    logger.error({ err }, "AI summary error");
    res.write(`data: ${JSON.stringify({ error: "AI generation failed" })}\n\n`);
    res.end();
  }
});

router.post("/ai/finding-advice/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const finding = await col("findings").findOne({ _id: new ObjectId(id) } as Record<string, unknown>);
    if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

    const prompt = `You are a senior security engineer. Write specific, actionable remediation guidance for this vulnerability.

Title: ${finding.title}
Severity: ${finding.severity}
CWE: ${finding.cwe_id ?? "N/A"}
CVSS Score: ${finding.cvss_score ?? "N/A"}
Endpoint: ${finding.endpoint}
Description: ${finding.description}

Provide:
1. Root cause explanation (1-2 sentences)
2. Step-by-step fix with a code example where applicable
3. How to verify the fix was applied correctly
4. Prevention measures for similar issues

Be concrete and developer-friendly.`;

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");

    const stream = anthropic.messages.stream({
      model: "claude-sonnet-4-6",
      max_tokens: 8192,
      messages: [{ role: "user", content: prompt }],
    });

    for await (const event of stream) {
      if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
        res.write(`data: ${JSON.stringify({ content: event.delta.text })}\n\n`);
      }
    }

    res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
    res.end();
  } catch (err) {
    logger.error({ err }, "AI advice error");
    res.write(`data: ${JSON.stringify({ error: "AI generation failed" })}\n\n`);
    res.end();
  }
});

// POST /ai/chat — General AI triage chat with system prompt + conversation history
router.post("/ai/chat", async (req, res) => {
  try {
    const { message, system, history = [] } = req.body as {
      message: string;
      system?: string;
      history?: Array<{ role: "user" | "assistant"; content: string }>;
    };

    if (!message) { res.status(400).json({ error: "message is required" }); return; }

    const systemPrompt = system ?? "You are a senior security engineer and penetration testing expert. Help users understand, triage, and remediate security vulnerabilities. Be direct, technical, and actionable.";

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");

    const messages = [
      ...history.slice(-10),
      { role: "user" as const, content: message },
    ];

    const stream = anthropic.messages.stream({
      model: "claude-sonnet-4-6",
      max_tokens: 4096,
      system: systemPrompt,
      messages,
    });

    for await (const event of stream) {
      if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
        res.write(`data: ${JSON.stringify({ content: event.delta.text })}\n\n`);
      }
    }

    res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
    res.end();
  } catch (err) {
    logger.error({ err }, "AI chat error");
    res.write(`data: ${JSON.stringify({ error: "AI generation failed" })}\n\n`);
    res.end();
  }
});

// POST /ai/payloads/:id — Generate attack payloads for a specific finding
router.post("/ai/payloads/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const finding = await col("findings").findOne({ _id: new ObjectId(id) } as Record<string, unknown>);
    if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

    const prompt = `You are a penetration tester generating specific attack payloads for authorized security testing.

Vulnerability: ${finding.title}
Category: ${finding.category}
CWE: ${finding.cwe_id ?? "N/A"}
Endpoint: ${finding.endpoint}
Evidence: ${String(finding.evidence ?? "").slice(0, 300)}
Description: ${String(finding.description ?? "").slice(0, 300)}

Generate 5-8 specific, working attack payloads tailored to this vulnerability and endpoint.
For each payload:
- Show the exact payload string
- Explain where/how to inject it
- Describe what a successful exploitation looks like

Format as a numbered list with code blocks. This is for authorized penetration testing.`;

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");

    const stream = anthropic.messages.stream({
      model: "claude-sonnet-4-6",
      max_tokens: 3000,
      messages: [{ role: "user", content: prompt }],
    });

    for await (const event of stream) {
      if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
        res.write(`data: ${JSON.stringify({ content: event.delta.text })}\n\n`);
      }
    }

    res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
    res.end();
  } catch (err) {
    logger.error({ err }, "AI payloads error");
    res.write(`data: ${JSON.stringify({ error: "AI generation failed" })}\n\n`);
    res.end();
  }
});

// POST /ai/patch/:id — Generate remediation code patch for a finding
router.post("/ai/patch/:id", async (req, res) => {
  const { id } = req.params;
  const { tech_stack } = req.body as { tech_stack?: string };
  try {
    const finding = await col("findings").findOne({ _id: new ObjectId(id) } as Record<string, unknown>);
    if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

    const prompt = `You are a senior security engineer writing a production-ready code patch.

Vulnerability: ${finding.title}
CWE: ${finding.cwe_id ?? "N/A"}
CVSS: ${finding.cvss_score ?? "N/A"}
Endpoint: ${finding.endpoint}
Description: ${finding.description}
Recommended Fix: ${finding.recommended_fix}
${tech_stack ? `Tech Stack: ${tech_stack}` : ""}

Provide:
1. **Vulnerable code example** — show a generic example of the problematic pattern
2. **Fixed code** — the corrected version with inline comments explaining each change
3. **Security test** — a unit test or integration test to verify the fix works
4. **Deployment checklist** — 3-5 steps to safely deploy this fix

Use appropriate code blocks with language tags. Be specific and production-ready.`;

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");

    const stream = anthropic.messages.stream({
      model: "claude-sonnet-4-6",
      max_tokens: 4096,
      messages: [{ role: "user", content: prompt }],
    });

    for await (const event of stream) {
      if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
        res.write(`data: ${JSON.stringify({ content: event.delta.text })}\n\n`);
      }
    }

    res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
    res.end();
  } catch (err) {
    logger.error({ err }, "AI patch error");
    res.write(`data: ${JSON.stringify({ error: "AI generation failed" })}\n\n`);
    res.end();
  }
});

// POST /ai/executive-narrative/:id — Generate executive risk narrative for a scan
router.post("/ai/executive-narrative/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const scan = await col("scan_jobs").findOne({ _id: new ObjectId(id) } as Record<string, unknown>);
    if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }

    const findings = await col("findings").find({ scan_job_id: new ObjectId(id) } as Record<string, unknown>).toArray();
    const criticals = findings.filter((f: Record<string, unknown>) => f.severity === "critical");
    const highs = findings.filter((f: Record<string, unknown>) => f.severity === "high");
    const categories = [...new Set(findings.map((f: Record<string, unknown>) => f.category))].slice(0, 8);

    const prompt = `You are a CISO writing an executive security briefing for C-suite leadership.

Target System: ${scan.target_url}
Assessment Date: ${new Date(scan.created_at as string).toLocaleDateString()}
Risk Score: ${scan.risk_score ?? 0}/100
Total Findings: ${findings.length} (${criticals.length} critical, ${highs.length} high)
Vulnerability Categories: ${categories.join(", ")}

Critical Issues:
${criticals.slice(0, 5).map((f: Record<string, unknown>) => `- ${f.title}: ${String(f.description ?? "").slice(0, 80)}`).join("\n") || "None"}

High Issues:
${highs.slice(0, 5).map((f: Record<string, unknown>) => `- ${f.title}: ${String(f.description ?? "").slice(0, 80)}`).join("\n") || "None"}

Write a 4-paragraph executive narrative:
1. **Executive Summary** — Overall security posture in business terms (no jargon)
2. **Business Risk** — What these vulnerabilities mean for the business (financial, reputational, regulatory)
3. **Key Findings** — The 2-3 most important issues explained for non-technical leadership
4. **Recommended Actions** — Prioritized next steps with estimated effort and urgency

Write in plain English. Avoid technical jargon. Focus on business impact and risk.`;

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");

    const stream = anthropic.messages.stream({
      model: "claude-sonnet-4-6",
      max_tokens: 2000,
      messages: [{ role: "user", content: prompt }],
    });

    for await (const event of stream) {
      if (event.type === "content_block_delta" && event.delta.type === "text_delta") {
        res.write(`data: ${JSON.stringify({ content: event.delta.text })}\n\n`);
      }
    }

    res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
    res.end();
  } catch (err) {
    logger.error({ err }, "AI executive narrative error");
    res.write(`data: ${JSON.stringify({ error: "AI generation failed" })}\n\n`);
    res.end();
  }
});

export default router;
