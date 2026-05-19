import { Router } from "express";
import { ObjectId } from "mongodb";
import OpenAI from "openai";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { aiLimiter } from "../middlewares/rate-limit";
import { requireAuth } from "../middlewares/rbac";

// ── Redis-backed response cache (TTL: 1 hour) ────────────────────────────────
import { redisGet, redisSet } from "../lib/redis";

const AI_CACHE_TTL_SECONDS = 60 * 60;

async function getCached(key: string): Promise<string | null> {
  return redisGet(`ai:cache:${key}`);
}

async function setCached(key: string, text: string): Promise<void> {
  await redisSet(`ai:cache:${key}`, text, AI_CACHE_TTL_SECONDS);
}

// ── Token usage tracking + budget enforcement ─────────────────────────────────
const AI_DAILY_TOKEN_BUDGET = parseInt(process.env["AI_DAILY_TOKEN_BUDGET"] ?? "50000");
// Per-conversation cap: max tokens a single chat session can accumulate
const AI_CONVERSATION_TOKEN_CAP = parseInt(process.env["AI_CONVERSATION_TOKEN_CAP"] ?? "8000");

async function getUserDailyTokens(userId: string): Promise<number> {
  const start = new Date();
  start.setHours(0, 0, 0, 0);
  const agg = await col("ai_usage").aggregate([
    { $match: { user_id: userId, created_at: { $gte: start } } },
    { $group: { _id: null, total: { $sum: "$estimated_tokens" } } },
  ]).toArray() as Array<Record<string, unknown>>;
  return Number((agg[0] as Record<string, unknown> | undefined)?.["total"] ?? 0);
}

async function logUsage(endpoint: string, resourceId: string, responseText: string, userId?: string): Promise<void> {
  const estimatedTokens = Math.ceil(responseText.length / 4);
  col("ai_usage").insertOne({ endpoint, resource_id: resourceId, estimated_tokens: estimatedTokens, user_id: userId ?? null, created_at: new Date() }).catch(() => {});
}

// ── Prompt injection sanitization ────────────────────────────────────────────
function sanitize(text: string, maxLen = 500): string {
  return String(text ?? "")
    .slice(0, maxLen)
    .replace(/```/g, "` ` `")
    .replace(/\[INST\]|\[\/INST\]|<s>|<\/s>|<\|im_start\|>|<\|im_end\|>/gi, "")
    .replace(/ignore (all |previous |prior )?(instructions?|prompts?|context)/gi, "[filtered]")
    .trim();
}

// ── Helpers ──────────────────────────────────────────────────────────────────

import { vault } from "../lib/vault";

async function getOpenAI() {
  const apiKey = await vault.getSecret("OPENCODE_API_KEY");
  return new OpenAI({
    apiKey: apiKey || "",
    baseURL: process.env["OPENCODE_API_BASE"] ?? "https://opencode.ai/zen/v1",
    timeout: 240000,
  });
}

function getModel() {
  return process.env["OPENCODE_MODEL"] ?? "nemotron-3-super-free";
}

function startSseHeartbeat(res: import("express").Response): NodeJS.Timeout {
  return setInterval(() => {
    if (!res.writableEnded) res.write(": keep-alive\n\n");
  }, 15000);
}

// Returns the full accumulated response text.
async function streamWithRetry(
  res: import("express").Response,
  buildRequest: () => Omit<OpenAI.Chat.Completions.ChatCompletionCreateParamsStreaming, "stream">,
  maxRetries = 2,
  signal?: AbortSignal
): Promise<string> {
  let lastErr: unknown;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    if (signal?.aborted) break;
    try {
      const openai = await getOpenAI();
      const stream = await openai.chat.completions.create(
        { ...buildRequest(), stream: true },
        { signal }
      );
      let accumulated = "";
      for await (const chunk of stream) {
        if (signal?.aborted) break;
        const text = chunk.choices[0]?.delta?.content;
        if (text) {
          accumulated += text;
          if (!res.writableEnded) res.write(`data: ${JSON.stringify({ content: text })}\n\n`);
        }
      }
      if (!signal?.aborted && !res.writableEnded) {
        res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
      }
      return accumulated;
    } catch (err) {
      lastErr = err;
      if (signal?.aborted) break;
      const msg = err instanceof Error ? err.message : String(err);
      const isRetriable = msg.includes("524") || msg.includes("Provider returned error") || msg.includes("timeout") || msg.includes("ECONNRESET");
      if (!isRetriable || attempt === maxRetries) break;
      const delay = 2000 * Math.pow(2, attempt);
      logger.warn({ attempt, delay }, "AI stream error — retrying");
      if (!res.writableEnded) res.write(`: retry attempt ${attempt + 1}\n\n`);
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  if (!signal?.aborted) throw lastErr;
  return "";
}

function setupSse(res: import("express").Response) {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
}

// Shared expert persona injected as system message on every endpoint.
function securityExpertSystem(): string {
  return `You are Marcus, a senior offensive security engineer with 15 years of experience across red team operations, bug bounty hunting, and secure code review. You hold OSCP, OSCE3, and CREST CRT certifications.

Your communication style:
- Direct, precise, and technical — no filler sentences
- Use exact CVE/CWE IDs, CVSS vectors, and MITRE ATT\&CK TTP IDs when relevant
- Always ground recommendations in real-world exploitability, not just theoretical risk
- Format responses with clear sections using markdown headers
- When generating code, always use proper language-tagged fenced code blocks
- Never hedge with "might" or "could" — state what IS exploitable and HOW`;
}

// Vuln-type branching for payload generation.
function buildPayloadPrompt(finding: Record<string, unknown>): string {
  const title = sanitize(String(finding["title"] ?? ""), 200);
  const category = String(finding["category"] ?? "").toLowerCase();
  const endpoint = sanitize(String(finding["endpoint"] ?? ""), 200);
  const evidence = sanitize(String(finding["evidence"] ?? ""), 300);
  const cwe = String(finding["cwe_id"] ?? "N/A");

  let categoryGuidance = "";

  if (category.includes("xss") || category.includes("cross-site")) {
    categoryGuidance = "Focus on: context-aware XSS (HTML/attribute/JS/URL context), filter bypass techniques, CSP bypass payloads, DOM-based variants. Include cookie theft, keystroke capture, and CSRF token exfiltration payloads.";
  } else if (category.includes("sql")) {
    categoryGuidance = "Focus on: error-based, blind boolean-based, time-based blind, UNION-based, and OOB SQLi. Include database fingerprinting, privilege escalation (xp_cmdshell/INTO OUTFILE), and WAF bypass techniques.";
  } else if (category.includes("ssrf")) {
    categoryGuidance = "Focus on: localhost bypass payloads (IPv6, decimal IP, URL encoding), cloud metadata endpoints (AWS 169.254.169.254, GCP, Azure IMDS), internal port scanning, protocol smuggling (gopher://, dict://, file://), DNS rebinding.";
  } else if (category.includes("idor") || category.includes("access control") || category.includes("bola")) {
    categoryGuidance = "Focus on: sequential ID enumeration, UUID predictability, horizontal/vertical privilege escalation, parameter pollution to bypass access controls.";
  } else if (category.includes("ssti") || category.includes("template")) {
    categoryGuidance = "Focus on: detection polyglot payloads, engine fingerprinting (Jinja2, Twig, FreeMarker, Pebble, Velocity, Smarty), RCE escalation chains per engine, sandbox escape.";
  } else if (category.includes("xxe")) {
    categoryGuidance = "Focus on: classic file read (/etc/passwd, AWS credentials), blind XXE with OOB exfiltration, XXE-to-SSRF pivoting, DoS via billion laughs, DTD injection via parameter entities.";
  } else if (category.includes("path") || category.includes("lfi") || category.includes("rfi") || category.includes("traversal")) {
    categoryGuidance = "Focus on: encoding bypasses (URL, double URL, Unicode), null byte injection, path normalization bypasses, log poisoning for RCE, PHP wrappers (php://filter, php://input, data://).";
  } else if (category.includes("cmd") || category.includes("command") || category.includes("rce")) {
    categoryGuidance = "Focus on: OS command separator chains (;, &&, ||, backtick, $()), IFS bypass, blind injection with OOB callback, filter bypass via env vars, reverse shell payloads.";
  } else if (category.includes("deserializ")) {
    categoryGuidance = "Focus on: gadget chain identification (Java ysoserial, Python pickle, PHP unserialize), DNS callback confirmation payloads, RCE escalation chains.";
  } else if (category.includes("jwt")) {
    categoryGuidance = "Focus on: none algorithm attack, RS256→HS256 confusion, weak secret brute-force, kid header injection (SQLi/path traversal), jku/x5u URL injection, claim manipulation.";
  } else if (category.includes("cors")) {
    categoryGuidance = "Focus on: origin reflection exploitation, null origin bypass, subdomain wildcard abuse. Include PoC JavaScript fetch code demonstrating credential theft.";
  } else {
    categoryGuidance = "Focus on detection payloads, exploitation payloads that confirm impact, filter bypass variants, and OOB confirmation payloads tailored to the endpoint and evidence.";
  }

  return `## Task: Generate Attack Payloads

**Vulnerability:** ${title}
**Category:** ${category} | **CWE:** ${cwe}
**Target Endpoint:** ${endpoint}
**Evidence/Context:** ${evidence}

${categoryGuidance}

Generate **8-10 specific attack payloads** for authorized penetration testing. For each payload:

1. **Payload** — exact string in a code block
2. **Injection Point** — where and how to inject it (parameter name, header, body field)
3. **Expected Response** — what a successful hit looks like
4. **Bypass Technique** — if this bypasses a specific filter or WAF rule, explain it

End with a **"Detection Tips"** section listing Burp Suite intruder settings, nuclei template tags, or grep patterns to detect this vulnerability class.`;
}

// Serve a cached SSE response.
function serveCachedSse(res: import("express").Response, text: string): void {
  setupSse(res);
  res.write(`data: ${JSON.stringify({ content: text })}\n\n`);
  res.write(`data: ${JSON.stringify({ done: true, cached: true })}\n\n`);
  res.end();
}

// Check Redis cache and serve SSE if hit. Returns true if served from cache.
async function serveCacheIfHit(res: import("express").Response, cacheKey: string): Promise<boolean> {
  const cached = await getCached(cacheKey);
  if (cached) { serveCachedSse(res, cached); return true; }
  return false;
}

// ── Confidence scoring ────────────────────────────────────────────────────────

function estimateConfidence(text: string, inputLength: number): number {
  const hedgeWords = ["might", "could", "possibly", "uncertain", "unclear", "may", "perhaps"];
  const hedgeCount = hedgeWords.filter(w => text.toLowerCase().includes(w)).length;
  const lengthRatio = Math.min(text.length / Math.max(inputLength, 1), 2);
  return Math.round(Math.min(95, Math.max(40, 85 - hedgeCount * 4 + lengthRatio * 3)));
}

// ── Routes ───────────────────────────────────────────────────────────────────

const router = Router();

router.use(aiLimiter);

// ── Token budget check middleware ─────────────────────────────────────────────
router.use(requireAuth, async (req, res, next) => {
  if (req.method !== "POST") return next();
  const session = (req as unknown as { session: { userId?: string } }).session;
  const userId = session.userId;
  if (!userId) return next();
  try {
    const used = await getUserDailyTokens(userId);
    if (used >= AI_DAILY_TOKEN_BUDGET) {
      return res.status(429).json({ error: "Daily AI token budget exceeded. Resets at midnight UTC." });
    }
  } catch { /* non-fatal */ }
  next();
});

// GET /api/ai/usage — current user token usage today
router.get("/ai/usage", async (req, res) => {
  const session = (req as unknown as { session: { userId?: string; role?: string } }).session;
  const userId = session.userId ?? "";
  const used = await getUserDailyTokens(userId);
  res.json({ used, budget: AI_DAILY_TOKEN_BUDGET, remaining: Math.max(0, AI_DAILY_TOKEN_BUDGET - used) });
});

// GET /api/ai/usage/all — admin: token usage per user today
router.get("/ai/usage/all", async (req, res) => {
  const session = (req as unknown as { session: { role?: string } }).session;
  if (session.role !== "admin") return res.status(403).json({ error: "Forbidden" });
  const start = new Date();
  start.setHours(0, 0, 0, 0);
  const agg = await col("ai_usage").aggregate([
    { $match: { created_at: { $gte: start } } },
    { $group: { _id: "$user_id", total_tokens: { $sum: "$estimated_tokens" }, calls: { $sum: 1 } } },
    { $sort: { total_tokens: -1 } },
  ]).toArray();
  res.json(agg);
});

// ── User model preference helper ──────────────────────────────────────────────

async function getUserModel(userId: string): Promise<string> {
  try {
    const userSettings = await col("users").findOne({ _id: new ObjectId(userId) });
    return (userSettings?.["settings"]?.["ai_model"] as string) || getModel();
  } catch {
    return getModel();
  }
}

// ── Scan Summary ──────────────────────────────────────────────────────────────
router.post("/ai/scan-summary/:id", async (req, res) => {
  const id = String(req.params["id"]);
  const cacheKey = `scan-summary:${id}`;
  if (await serveCacheIfHit(res, cacheKey)) return;

  const abort = new AbortController();
  req.on("close", () => abort.abort());

  const session = (req as unknown as { session: { userId?: string } }).session;
  const model = await getUserModel(session.userId ?? "");

  try {
    const scan = await col("scan_jobs").findOne({ _id: new ObjectId(id) } as Record<string, unknown>);
    if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }

    const findings = await col("findings").find({ scan_job_id: new ObjectId(id) } as Record<string, unknown>).toArray();
    const criticals = findings.filter((f: Record<string, unknown>) => f.severity === "critical");
    const highs = findings.filter((f: Record<string, unknown>) => f.severity === "high");
    const mediums = findings.filter((f: Record<string, unknown>) => f.severity === "medium");
    const topFindings = [...criticals, ...highs].slice(0, 8).map((f: Record<string, unknown>) =>
      `- [${String(f.severity).toUpperCase()}] ${sanitize(String(f.title), 120)} — ${sanitize(String(f.endpoint), 80)} (CVSS: ${f.cvss_score ?? "N/A"}, CWE: ${f.cwe_id ?? "N/A"})`
    ).join("\n");
    const categories = [...new Set(findings.map((f: Record<string, unknown>) => f.category))].filter(Boolean);

    const userContent = `## Security Assessment Summary Request\n\n**Target:** ${scan.target_url}\n**Risk Score:** ${scan.risk_score}/100\n**Findings:** ${findings.length} total — Critical: ${criticals.length}, High: ${highs.length}, Medium: ${mediums.length}\n**Vulnerability Categories:** ${categories.join(", ") || "N/A"}\n\n**Top Critical/High Findings:**\n${topFindings || "No critical/high findings."}\n\nWrite a professional **3-paragraph executive summary**:\n\n**Paragraph 1 — Security Posture:** Overall risk level, attack surface assessment, and how this compares to industry benchmarks.\n\n**Paragraph 2 — Critical Issues & Business Impact:** The most dangerous findings, their real-world exploitability, potential data exposure, and regulatory implications (GDPR, PCI-DSS, SOC2 where relevant).\n\n**Paragraph 3 — Immediate Actions:** Specific, prioritized remediation steps with rough effort estimates. Lead with highest-impact quick wins.\n\nWrite in flowing paragraphs. No bullet points. Professional tone suitable for a CISO briefing.`;
    const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
      { role: "system", content: securityExpertSystem() },
      { role: "user", content: userContent },
    ];

    setupSse(res);
    const hb = startSseHeartbeat(res);
    try {
      const text = await streamWithRetry(res, () => ({ model, max_tokens: 1800, messages }), 2, abort.signal);
      if (text) {
        setCached(cacheKey, text).catch(() => {});
        logUsage("scan-summary", id, text);
        if (!res.writableEnded) res.write(`data: ${JSON.stringify({ done: true, confidence: estimateConfidence(text, userContent.length) })}\n\n`);
      }
    } finally { clearInterval(hb); if (!res.writableEnded) res.end(); }
  } catch (err) {
    logger.error({ err }, "AI summary error");
    if (!res.writableEnded) { res.write(`data: ${JSON.stringify({ error: "AI generation failed" })}\n\n`); res.end(); }
  }
});

// ── Finding Advice ────────────────────────────────────────────────────────────
router.post("/ai/finding-advice/:id", async (req, res) => {
  const id = String(req.params["id"]);
  const cacheKey = `finding-advice:${id}`;
  if (await serveCacheIfHit(res, cacheKey)) return;

  const abort = new AbortController();
  req.on("close", () => abort.abort());

  const session = (req as unknown as { session: { userId?: string } }).session;
  const model = await getUserModel(session.userId ?? "");

  try {
    const finding = await col("findings").findOne({ _id: new ObjectId(id) } as Record<string, unknown>);
    if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

    const userContent = `## Remediation Guidance Request\n\n**Vulnerability:** ${sanitize(String(finding.title), 200)}\n**Severity:** ${finding.severity} | **CVSS:** ${finding.cvss_score ?? "N/A"} | **CWE:** ${finding.cwe_id ?? "N/A"}\n**Endpoint:** ${sanitize(String(finding.endpoint), 200)}\n**Description:** ${sanitize(String(finding.description ?? ""), 500)}\n**Evidence:** ${sanitize(String(finding.evidence ?? ""), 300)}\n\n## Root Cause Analysis\nExplain the underlying programming mistake or architectural flaw. Be specific about the code pattern.\n\n## Step-by-Step Fix\nShow:\n- Vulnerable code snippet (labeled \`// VULNERABLE\`)\n- Fixed code snippet (labeled \`// FIXED\`) with inline comments\n\n## Verification Steps\nHow to confirm the fix works — include a specific test case or curl command.\n\n## Prevention Measures\n3-4 concrete engineering controls (input validation library, security header, framework config, CI/CD check).\n\n## Related Vulnerabilities to Check\nList 2-3 related CWEs or attack variants to audit in the same codebase.`;
    const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
      { role: "system", content: securityExpertSystem() },
      { role: "user", content: userContent },
    ];

    setupSse(res);
    const hb = startSseHeartbeat(res);
    try {
      const text = await streamWithRetry(res, () => ({ model, max_tokens: 2000, messages }), 2, abort.signal);
      if (text) {
        setCached(cacheKey, text).catch(() => {});
        logUsage("finding-advice", id, text);
        if (!res.writableEnded) res.write(`data: ${JSON.stringify({ done: true, confidence: estimateConfidence(text, userContent.length) })}\n\n`);
      }
    } finally { clearInterval(hb); if (!res.writableEnded) res.end(); }
  } catch (err) {
    logger.error({ err }, "AI advice error");
    if (!res.writableEnded) { res.write(`data: ${JSON.stringify({ error: "AI generation failed" })}\n\n`); res.end(); }
  }
});

// ── Chat ──────────────────────────────────────────────────────────────────────
router.post("/ai/chat", async (req, res) => {
  const abort = new AbortController();
  req.on("close", () => abort.abort());

  const session = (req as unknown as { session: { userId?: string } }).session;
  const model = await getUserModel(session.userId ?? "");

  try {
    const { message, system, history = [], scan_id, context } = req.body as {
      message: string; system?: string;
      history?: Array<{ role: "user" | "assistant"; content: string }>;
      scan_id?: string;
      context?: { target?: string; findings_count?: number; top_severity?: string };
    };
    if (!message) { res.status(400).json({ error: "message is required" }); return; }

    // Per-conversation token cap: estimate tokens already used in this history
    const conversationTokens = history.reduce((sum, m) => sum + Math.ceil(m.content.length / 4), 0);
    if (conversationTokens >= AI_CONVERSATION_TOKEN_CAP) {
      res.status(429).json({ error: `Conversation token limit reached (${AI_CONVERSATION_TOKEN_CAP} estimated tokens). Start a new conversation.` });
      return;
    }

    let contextBlock = "";
    if (scan_id && context) {
      contextBlock = `\n\n## Current Scan Context\n- Target: ${context.target ?? "unknown"}\n- Total Findings: ${context.findings_count ?? 0}\n- Highest Severity: ${context.top_severity ?? "unknown"}`;
    }

    const systemPrompt = system ?? `${securityExpertSystem()}${contextBlock}\n\nYou are the AI assistant embedded in Bug Finder Pro. Users are security engineers, pentesters, and developers. Give concrete technical answers — not generic advice.`;
    const sanitizedMsg = sanitize(message, 2000);

    const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
      { role: "system", content: systemPrompt },
      ...history.slice(-12),
      { role: "user", content: sanitizedMsg },
    ];

    setupSse(res);
    const hb = startSseHeartbeat(res);
    try {
      const text = await streamWithRetry(res, () => ({ model, max_tokens: 2500, messages }), 2, abort.signal);
      if (text && !res.writableEnded) {
        res.write(`data: ${JSON.stringify({ done: true, confidence: estimateConfidence(text, sanitizedMsg.length) })}\n\n`);
      }
    } finally { clearInterval(hb); if (!res.writableEnded) res.end(); }
  } catch (err) {
    logger.error({ err }, "AI chat error");
    if (!res.writableEnded) { res.write(`data: ${JSON.stringify({ error: "AI generation failed" })}\n\n`); res.end(); }
  }
});

// ── Payloads ──────────────────────────────────────────────────────────────────
router.post("/ai/payloads/:id", async (req, res) => {
  const id = String(req.params["id"]);
  const cacheKey = `payloads:${id}`;
  if (await serveCacheIfHit(res, cacheKey)) return;

  const abort = new AbortController();
  req.on("close", () => abort.abort());

  const session = (req as unknown as { session: { userId?: string } }).session;
  const model = await getUserModel(session.userId ?? "");

  try {
    const finding = await col("findings").findOne({ _id: new ObjectId(id) } as Record<string, unknown>);
    if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

    const userContent = buildPayloadPrompt(finding as Record<string, unknown>);
    const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
      { role: "system", content: securityExpertSystem() },
      { role: "user", content: userContent },
    ];

    setupSse(res);
    const hb = startSseHeartbeat(res);
    try {
      const text = await streamWithRetry(res, () => ({ model, max_tokens: 2500, messages }), 2, abort.signal);
      if (text) {
        setCached(cacheKey, text).catch(() => {});
        logUsage("payloads", id, text);
        if (!res.writableEnded) res.write(`data: ${JSON.stringify({ done: true, confidence: estimateConfidence(text, userContent.length) })}\n\n`);
      }
    } finally { clearInterval(hb); if (!res.writableEnded) res.end(); }
  } catch (err) {
    logger.error({ err }, "AI payloads error");
    if (!res.writableEnded) { res.write(`data: ${JSON.stringify({ error: "AI generation failed" })}\n\n`); res.end(); }
  }
});

// ── Patch ─────────────────────────────────────────────────────────────────────
router.post("/ai/patch/:id", async (req, res) => {
  const id = String(req.params["id"]);
  const { tech_stack } = req.body as { tech_stack?: string };
  const cacheKey = `patch:${id}:${tech_stack ?? ""}`;
  if (await serveCacheIfHit(res, cacheKey)) return;

  const abort = new AbortController();
  req.on("close", () => abort.abort());

  const session = (req as unknown as { session: { userId?: string } }).session;
  const model = await getUserModel(session.userId ?? "");

  try {
    const finding = await col("findings").findOne({ _id: new ObjectId(id) } as Record<string, unknown>);
    if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

    const userContent = `## Production-Ready Security Patch Request\n\n**Vulnerability:** ${sanitize(String(finding.title), 200)}\n**CWE:** ${finding.cwe_id ?? "N/A"} | **CVSS:** ${finding.cvss_score ?? "N/A"}\n**Endpoint:** ${sanitize(String(finding.endpoint), 200)}\n**Recommended Fix:** ${sanitize(String(finding.recommended_fix ?? ""), 300)}${tech_stack ? `\n**Tech Stack:** ${tech_stack}` : ""}\n\n## Vulnerable Code\nShow a realistic snippet demonstrating the vulnerability.\n\n## Fixed Code\nPatched version with inline comments explaining each security control.\n\n## Security Unit Test\nA specific test case verifying the fix prevents exploitation.\n\n## Deployment Checklist\n- [ ] items the developer must verify before deploying.\n\n## References\nCWE link, OWASP cheat sheet link, relevant CVEs.`;
    const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
      { role: "system", content: securityExpertSystem() },
      { role: "user", content: userContent },
    ];

    setupSse(res);
    const hb = startSseHeartbeat(res);
    try {
      const text = await streamWithRetry(res, () => ({ model, max_tokens: 3000, messages }), 2, abort.signal);
      if (text) {
        setCached(cacheKey, text).catch(() => {});
        logUsage("patch", id, text);
        if (!res.writableEnded) res.write(`data: ${JSON.stringify({ done: true, confidence: estimateConfidence(text, userContent.length) })}\n\n`);
      }
    } finally { clearInterval(hb); if (!res.writableEnded) res.end(); }
  } catch (err) {
    logger.error({ err }, "AI patch error");
    if (!res.writableEnded) { res.write(`data: ${JSON.stringify({ error: "AI generation failed" })}\n\n`); res.end(); }
  }
});

// ── Executive Narrative ───────────────────────────────────────────────────────
router.post("/ai/executive-narrative/:id", async (req, res) => {
  const id = String(req.params["id"]);
  const cacheKey = `exec-narrative:${id}`;
  if (await serveCacheIfHit(res, cacheKey)) return;

  const abort = new AbortController();
  req.on("close", () => abort.abort());

  const session = (req as unknown as { session: { userId?: string } }).session;
  const model = await getUserModel(session.userId ?? "");

  try {
    const scan = await col("scan_jobs").findOne({ _id: new ObjectId(id) } as Record<string, unknown>);
    if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }

    const findings = await col("findings").find({ scan_job_id: new ObjectId(id) } as Record<string, unknown>).toArray();
    const criticals = findings.filter((f: Record<string, unknown>) => f.severity === "critical");
    const highs = findings.filter((f: Record<string, unknown>) => f.severity === "high");
    const categories = [...new Set(findings.map((f: Record<string, unknown>) => f.category))].slice(0, 6);

    const userContent = `## Executive Security Briefing Request\n\n**Target:** ${scan.target_url} | **Risk Score:** ${scan.risk_score ?? 0}/100\n**Findings:** ${findings.length} total (${criticals.length} critical, ${highs.length} high)\n**Categories:** ${categories.join(", ")}\n**Critical Issues:** ${criticals.slice(0, 3).map((f: Record<string, unknown>) => sanitize(String(f.title), 80)).join("; ") || "None"}\n\nWrite 4 C-suite paragraphs in plain business English:\n\n1) **Executive Summary** — What was assessed, bottom-line risk verdict, urgency level.\n2) **Business Risk** — Financial/reputational/regulatory exposure. Reference GDPR, PCI-DSS, SOC 2 where relevant.\n3) **Key Findings (Non-Technical)** — 2-3 most important vulnerabilities using analogies a CEO understands.\n4) **Recommended Actions & Timeline** — Prioritized plan with realistic milestones (Week 1, Month 1, Quarter 1).\n\nNo bullet points. No jargon. Written for a board audience.`;
    const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
      { role: "system", content: securityExpertSystem() },
      { role: "user", content: userContent },
    ];

    setupSse(res);
    const hb = startSseHeartbeat(res);
    try {
      const text = await streamWithRetry(res, () => ({ model, max_tokens: 1800, messages }), 2, abort.signal);
      if (text) {
        setCached(cacheKey, text).catch(() => {});
        logUsage("exec-narrative", id, text);
        if (!res.writableEnded) res.write(`data: ${JSON.stringify({ done: true, confidence: estimateConfidence(text, userContent.length) })}\n\n`);
      }
    } finally { clearInterval(hb); if (!res.writableEnded) res.end(); }
  } catch (err) {
    logger.error({ err }, "AI executive narrative error");
    if (!res.writableEnded) { res.write(`data: ${JSON.stringify({ error: "AI generation failed" })}\n\n`); res.end(); }
  }
});

// ── Attack Chain ──────────────────────────────────────────────────────────────
router.post("/ai/attack-chain/:scanId", async (req, res) => {
  const { scanId } = req.params;
  const cacheKey = `attack-chain:${scanId}`;
  if (await serveCacheIfHit(res, cacheKey)) return;

  const abort = new AbortController();
  req.on("close", () => abort.abort());

  const session = (req as unknown as { session: { userId?: string } }).session;
  const model = await getUserModel(session.userId ?? "");

  try {
    setupSse(res);
    const hb = startSseHeartbeat(res);
    const findings = await col("findings").find({ scan_job_id: new ObjectId(scanId) } as Record<string, unknown>).toArray() as Array<Record<string, unknown>>;
    if (!findings.length) { res.write(`data: ${JSON.stringify({ done: true })}\n\n`); res.end(); clearInterval(hb); return; }
    const list = findings.map(f => `[${String(f["severity"]).toUpperCase()}] ${sanitize(String(f["title"]), 100)} @ ${sanitize(String(f["endpoint"]), 80)} (${f["category"]}) — CWE: ${f["cwe_id"] ?? "N/A"}`).join("\n");

    const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
      { role: "system", content: securityExpertSystem() },
      { role: "user", content: `## Attack Chain Analysis\n\nAnalyze these findings and identify realistic multi-step attack chains.\n\n**Findings:**\n${list}\n\nFor each chain:\n\n### Chain [N]: [Name]\n**MITRE ATT&CK TTPs:** List TTP IDs (T1190, T1078, T1059, etc.)\n**Steps:** Numbered exploitation steps\n**Combined Severity:** Critical/High/Medium\n**Time to Exploit:** Estimated hours for a skilled attacker\n**Business Impact:** Specific damage\n**Detection Opportunity:** Where a defender could break the chain\n\nIdentify 2-4 chains. Prioritize chains starting from unauthenticated access.` },
    ];

    try {
      const text = await streamWithRetry(res, () => ({ model, messages, max_tokens: 1800 }), 2, abort.signal);
      if (text) { setCached(cacheKey, text).catch(() => {}); logUsage("attack-chain", scanId, text); }
    } finally { clearInterval(hb); if (!res.writableEnded) res.end(); }
  } catch (err) {
    logger.error({ err }, "attack-chain error");
    if (!res.writableEnded) res.write(`data: ${JSON.stringify({ error: "AI unavailable" })}\n\n`);
    if (!res.writableEnded) res.end();
  }
});

// ── PoC Generation ────────────────────────────────────────────────────────────
router.post("/ai/poc/:findingId", async (req, res) => {
  const findingId = String(req.params["findingId"]);
  const cacheKey = `poc:${findingId}`;
  if (await serveCacheIfHit(res, cacheKey)) return;

  const abort = new AbortController();
  req.on("close", () => abort.abort());

  const session = (req as unknown as { session: { userId?: string } }).session;
  const model = await getUserModel(session.userId ?? "");

  try {
    setupSse(res);
    const hb = startSseHeartbeat(res);
    const f = await col("findings").findOne({ _id: new ObjectId(findingId) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!f) { res.write(`data: ${JSON.stringify({ done: true })}\n\n`); res.end(); clearInterval(hb); return; }

    const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
      { role: "system", content: securityExpertSystem() },
      { role: "user", content: `## Proof-of-Concept Generation\n\n**Vulnerability:** ${sanitize(String(f["title"]), 200)}\n**Endpoint:** ${sanitize(String(f["endpoint"]), 200)}\n**Description:** ${sanitize(String(f["description"] ?? ""), 400)}\n**Evidence:** ${sanitize(String(f["evidence"] ?? ""), 300)}\n**CWE:** ${f["cwe_id"]}\n\n## HTTP Request\nExact HTTP request that triggers the vulnerability.\n\n## Expected Vulnerable Response\nWhat the server returns when exploitation succeeds.\n\n## Curl Command\nReady-to-run curl command with placeholder values (TARGET, SESSION).\n\n## Minimal PoC Script\nShort Python script (under 30 lines) that automates the PoC.\n\n## Impact Confirmation\nHow to verify exploitation had the intended impact.\n\n## Detection Artifacts\nLog entries or network signatures a defender would see.` },
    ];

    try {
      const text = await streamWithRetry(res, () => ({ model, messages, max_tokens: 1800 }), 2, abort.signal);
      if (text) { setCached(cacheKey, text).catch(() => {}); logUsage("poc", findingId, text); }
    } finally { clearInterval(hb); if (!res.writableEnded) res.end(); }
  } catch (err) {
    logger.error({ err }, "poc error");
    if (!res.writableEnded) res.write(`data: ${JSON.stringify({ error: "AI unavailable" })}\n\n`);
    if (!res.writableEnded) res.end();
  }
});

// ── Scan Config ───────────────────────────────────────────────────────────────
router.post("/ai/scan-config", async (req, res) => {
  try {
    const { prompt: userPrompt } = req.body as { prompt?: string };
    if (!userPrompt) return res.status(400).json({ error: "prompt required" });
    const openai = await getOpenAI();
    const resp = await openai.chat.completions.create({
      model: getModel(), stream: false,
      messages: [
        { role: "system", content: "You are a security scan configuration parser. Extract structured scan parameters from natural language and return ONLY valid JSON, no markdown, no explanation." },
        { role: "user", content: `Convert this natural language scan request into JSON with keys: target_url (string), profile ("quick"|"standard"|"deep"), validation_enabled (bool), fuzzing_enabled (bool), bug_bounty_mode (bool), notes (string).\n\nRequest: "${sanitize(userPrompt, 500)}"` },
      ],
      max_tokens: 400,
    });
    const text = resp.choices[0]?.message?.content ?? "{}";
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    const config = jsonMatch ? JSON.parse(jsonMatch[0]) : {};
    res.json(config);
  } catch (err) {
    logger.error({ err }, "scan-config error");
    res.status(500).json({ error: "AI unavailable" });
  }
});

// ── Patch Diff ────────────────────────────────────────────────────────────────
router.post("/ai/patch-diff/:findingId", async (req, res) => {
  const findingId = String(req.params["findingId"]);
  const cacheKey = `patch-diff:${findingId}`;
  if (await serveCacheIfHit(res, cacheKey)) return;

  const abort = new AbortController();
  req.on("close", () => abort.abort());

  const session = (req as unknown as { session: { userId?: string } }).session;
  const model = await getUserModel(session.userId ?? "");

  try {
    setupSse(res);
    const hb = startSseHeartbeat(res);
    const f = await col("findings").findOne({ _id: new ObjectId(findingId) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!f) { res.write(`data: ${JSON.stringify({ done: true })}\n\n`); res.end(); clearInterval(hb); return; }

    const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
      { role: "system", content: securityExpertSystem() },
      { role: "user", content: `## Code Patch Diff Request\n\n**Vulnerability:** ${sanitize(String(f["title"]), 200)}\n**Endpoint:** ${sanitize(String(f["endpoint"]), 200)}\n**Description:** ${sanitize(String(f["description"] ?? ""), 400)}\n**Recommended Fix:** ${sanitize(String(f["recommended_fix"] ?? ""), 300)}\n\nProvide:\n1. A unified diff (\`\`\`diff) showing the exact change\n2. A brief explanation (2-3 sentences) of WHY the fix works\n3. Any additional package/config needed` },
    ];

    try {
      const text = await streamWithRetry(res, () => ({ model, messages, max_tokens: 1200 }), 2, abort.signal);
      if (text) { setCached(cacheKey, text).catch(() => {}); logUsage("patch-diff", findingId, text); }
    } finally { clearInterval(hb); if (!res.writableEnded) res.end(); }
  } catch (err) {
    logger.error({ err }, "patch-diff error");
    if (!res.writableEnded) res.write(`data: ${JSON.stringify({ error: "AI unavailable" })}\n\n`);
    if (!res.writableEnded) res.end();
  }
});

// ── Bug Bounty Report ─────────────────────────────────────────────────────────
router.post("/ai/bug-bounty-report/:findingId", async (req, res) => {
  const findingId = String(req.params["findingId"]);
  const cacheKey = `bb-report:${findingId}`;
  if (await serveCacheIfHit(res, cacheKey)) return;

  const abort = new AbortController();
  req.on("close", () => abort.abort());

  const session = (req as unknown as { session: { userId?: string } }).session;
  const model = await getUserModel(session.userId ?? "");

  try {
    setupSse(res);
    const hb = startSseHeartbeat(res);
    const f = await col("findings").findOne({ _id: new ObjectId(findingId) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!f) { res.write(`data: ${JSON.stringify({ done: true })}\n\n`); res.end(); clearInterval(hb); return; }

    const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
      { role: "system", content: securityExpertSystem() },
      { role: "user", content: `## Bug Bounty Report (HackerOne/Bugcrowd format)\n\n- Title: ${sanitize(String(f["title"]), 150)}\n- Severity: ${f["severity"]} | CVSS: ${f["cvss_score"]} | CWE: ${f["cwe_id"]}\n- Endpoint: ${sanitize(String(f["endpoint"]), 200)}\n- Description: ${sanitize(String(f["description"] ?? ""), 500)}\n- Evidence: ${sanitize(String(f["evidence"] ?? ""), 300)}\n- Recommended Fix: ${sanitize(String(f["recommended_fix"] ?? ""), 300)}\n\nStructure:\n# [Severity]: [Clear Title]\n## Summary\n## Severity & CVSS\n## Steps to Reproduce\n## Impact\n## Proof of Concept\n## Recommended Fix\n## References` },
    ];

    try {
      const text = await streamWithRetry(res, () => ({ model, messages, max_tokens: 2000 }), 2, abort.signal);
      if (text) { setCached(cacheKey, text).catch(() => {}); logUsage("bb-report", findingId, text); }
    } finally { clearInterval(hb); if (!res.writableEnded) res.end(); }
  } catch (err) {
    logger.error({ err }, "bug-bounty-report error");
    if (!res.writableEnded) res.write(`data: ${JSON.stringify({ error: "AI unavailable" })}\n\n`);
    if (!res.writableEnded) res.end();
  }
});

// ── Attack Narrative ──────────────────────────────────────────────────────────
router.post("/ai/attack-narrative/:findingId", async (req, res) => {
  const findingId = String(req.params["findingId"]);
  const cacheKey = `attack-narrative:${findingId}`;
  if (await serveCacheIfHit(res, cacheKey)) return;

  const abort = new AbortController();
  req.on("close", () => abort.abort());

  const session = (req as unknown as { session: { userId?: string } }).session;
  const model = await getUserModel(session.userId ?? "");

  try {
    setupSse(res);
    const hb = startSseHeartbeat(res);
    const f = await col("findings").findOne({ _id: new ObjectId(findingId) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!f) { res.write(`data: ${JSON.stringify({ done: true })}\n\n`); res.end(); clearInterval(hb); return; }

    const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
      { role: "system", content: securityExpertSystem() },
      { role: "user", content: `## Attack Narrative (for security awareness training)\n\n- Finding: ${sanitize(String(f["title"]), 150)}\n- Endpoint: ${sanitize(String(f["endpoint"]), 200)}\n- Description: ${sanitize(String(f["description"] ?? ""), 400)}\n- Evidence: ${sanitize(String(f["evidence"] ?? ""), 300)}\n\n**Paragraph 1 — Discovery:** How the attacker finds this vulnerability (Shodan, nuclei, Burp, OSINT). Specific signal that reveals it.\n\n**Paragraph 2 — Exploitation:** Exact steps, request/response, escalation path. Reference MITRE ATT&CK TTP IDs inline.\n\n**Paragraph 3 — Post-Exploitation:** Data exfiltration path, lateral movement, monetization (dark web prices, ransomware ranges).\n\nPast tense. Technical but readable.` },
    ];

    try {
      const text = await streamWithRetry(res, () => ({ model, messages, max_tokens: 900 }), 2, abort.signal);
      if (text) { setCached(cacheKey, text).catch(() => {}); logUsage("attack-narrative", findingId, text); }
    } finally { clearInterval(hb); if (!res.writableEnded) res.end(); }
  } catch (err) {
    logger.error({ err }, "attack-narrative error");
    if (!res.writableEnded) res.write(`data: ${JSON.stringify({ error: "AI unavailable" })}\n\n`);
    if (!res.writableEnded) res.end();
  }
});

// ── Tool Recommendations ──────────────────────────────────────────────────────
router.post("/ai/tools/:findingId", async (req, res) => {
  const findingId = String(req.params["findingId"]);
  const cacheKey = `tools:${findingId}`;
  if (await serveCacheIfHit(res, cacheKey)) return;

  const abort = new AbortController();
  req.on("close", () => abort.abort());

  const session = (req as unknown as { session: { userId?: string } }).session;
  const model = await getUserModel(session.userId ?? "");

  try {
    setupSse(res);
    const hb = startSseHeartbeat(res);
    const f = await col("findings").findOne({ _id: new ObjectId(findingId) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!f) { res.write(`data: ${JSON.stringify({ done: true })}\n\n`); res.end(); clearInterval(hb); return; }

    const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
      { role: "system", content: securityExpertSystem() },
      { role: "user", content: `## Security Tool Recommendations\n\n**Vulnerability:** ${sanitize(String(f["title"]), 150)}\n**Category:** ${f["category"]} | **CWE:** ${f["cwe_id"] ?? "N/A"}\n**Endpoint:** ${sanitize(String(f["endpoint"]), 200)}\n**Description:** ${sanitize(String(f["description"] ?? ""), 300)}\n\n## Burp Suite\nSpecific BApp extensions to install, scanner check names, Intruder/Repeater techniques.\n\n## CLI Tools\nFor each: name, install command, exact command to test this specific vuln. Include tools from: nuclei, sqlmap, ffuf, nikto, testssl.sh, jwt_tool, corsy, dalfox.\n\n## Nuclei Templates\nSpecific template tags or IDs with exact \`-t\` flag values.\n\n## Manual Testing Steps\n3-4 specific browser/Burp steps to confirm manually.\n\n## OSINT / Recon\nShodan dorks, Google dorks, GitHub dorking patterns for this vuln class.` },
    ];

    try {
      const text = await streamWithRetry(res, () => ({ model, messages, max_tokens: 1800 }), 2, abort.signal);
      if (text) { setCached(cacheKey, text).catch(() => {}); logUsage("tools", findingId, text); }
    } finally { clearInterval(hb); if (!res.writableEnded) res.end(); }
  } catch (err) {
    logger.error({ err }, "tools error");
    if (!res.writableEnded) res.write(`data: ${JSON.stringify({ error: "AI unavailable" })}\n\n`);
    if (!res.writableEnded) res.end();
  }
});

// ── Remediation Plan (full scan sprint plan) ──────────────────────────────────
router.post("/ai/remediation-plan/:scanId", async (req, res) => {
  const { scanId } = req.params;
  const cacheKey = `remediation-plan:${scanId}`;
  if (await serveCacheIfHit(res, cacheKey)) return;

  const abort = new AbortController();
  req.on("close", () => abort.abort());

  const session = (req as unknown as { session: { userId?: string } }).session;
  const model = await getUserModel(session.userId ?? "");

  try {
    setupSse(res);
    const hb = startSseHeartbeat(res);
    const scan = await col("scan_jobs").findOne({ _id: new ObjectId(scanId) } as Record<string, unknown>);
    if (!scan) { res.write(`data: ${JSON.stringify({ done: true })}\n\n`); res.end(); clearInterval(hb); return; }

    const findings = await col("findings").find({ scan_job_id: new ObjectId(scanId) } as Record<string, unknown>).toArray() as Array<Record<string, unknown>>;
    const list = findings.map(f =>
      `[${String(f["severity"]).toUpperCase()}] ${sanitize(String(f["title"]), 100)} | ${sanitize(String(f["endpoint"]), 80)} | CWE: ${f["cwe_id"] ?? "N/A"} | CVSS: ${f["cvss_score"] ?? "N/A"}`
    ).join("\n");

    const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
      { role: "system", content: securityExpertSystem() },
      { role: "user", content: `## Remediation Sprint Plan\n\n**Target:** ${scan.target_url} | **Risk Score:** ${scan.risk_score}/100\n\n**All Findings:**\n${list || "No findings."}\n\nCreate a prioritized remediation sprint plan for an engineering team. Structure as:\n\n## Sprint 1 — Week 1 (P0: Critical)\nFor each finding: title, estimated fix time, owner role (Frontend/Backend/DevOps), fix approach in one sentence.\n\n## Sprint 2 — Weeks 2-3 (P1: High)\nSame format.\n\n## Sprint 3 — Month 2 (P2: Medium + Systemic)\nSame format, plus systemic improvements (WAF rules, input validation library, security headers middleware).\n\n## Engineering Effort Summary\nTotal estimated hours by team. ROI framing: risk reduction per engineer-day.\n\nBe concrete. Every finding must appear exactly once.` },
    ];

    try {
      const text = await streamWithRetry(res, () => ({ model, messages, max_tokens: 2500 }), 2, abort.signal);
      if (text) { setCached(cacheKey, text).catch(() => {}); logUsage("remediation-plan", scanId, text); }
    } finally { clearInterval(hb); if (!res.writableEnded) res.end(); }
  } catch (err) {
    logger.error({ err }, "remediation-plan error");
    if (!res.writableEnded) res.write(`data: ${JSON.stringify({ error: "AI unavailable" })}\n\n`);
    if (!res.writableEnded) res.end();
  }
});

// ── False Positive Analysis ───────────────────────────────────────────────────
router.post("/ai/false-positive/:findingId", async (req, res) => {
  const findingId = String(req.params["findingId"]);
  const cacheKey = `fp-analysis:${findingId}`;
  if (await serveCacheIfHit(res, cacheKey)) return;

  const abort = new AbortController();
  req.on("close", () => abort.abort());

  const session = (req as unknown as { session: { userId?: string } }).session;
  const model = await getUserModel(session.userId ?? "");

  try {
    setupSse(res);
    const hb = startSseHeartbeat(res);
    const f = await col("findings").findOne({ _id: new ObjectId(findingId) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!f) { res.write(`data: ${JSON.stringify({ done: true })}\n\n`); res.end(); clearInterval(hb); return; }

    const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
      { role: "system", content: securityExpertSystem() },
      { role: "user", content: `## False Positive Analysis\n\nAnalyze whether this scanner finding is likely a real vulnerability or a false positive.\n\n**Title:** ${sanitize(String(f["title"]), 200)}\n**Category:** ${f["category"]} | **CWE:** ${f["cwe_id"] ?? "N/A"} | **CVSS:** ${f["cvss_score"] ?? "N/A"}\n**Endpoint:** ${sanitize(String(f["endpoint"]), 200)}\n**Description:** ${sanitize(String(f["description"] ?? ""), 400)}\n**Evidence:** ${sanitize(String(f["evidence"] ?? ""), 400)}\n**Scanner:** ${f["scanner_name"] ?? "unknown"}\n\n## Verdict\nState: **Real Vulnerability** or **Likely False Positive** or **Needs Manual Verification**\n\n## Confidence Score\nX/10 — confidence it is a real vulnerability. Explain the score.\n\n## Evidence Assessment\nWhat in the evidence supports or undermines the finding. Are the scanner's indicators conclusive?\n\n## False Positive Indicators\nList any signs this could be a FP: scanner over-detection patterns, context that makes exploitation impossible, missing preconditions.\n\n## Verification Steps\nExactly how to manually confirm whether this is real in under 10 minutes.` },
    ];

    try {
      const text = await streamWithRetry(res, () => ({ model, messages, max_tokens: 1400 }), 2, abort.signal);
      if (text) { setCached(cacheKey, text).catch(() => {}); logUsage("fp-analysis", findingId, text); }
    } finally { clearInterval(hb); if (!res.writableEnded) res.end(); }
  } catch (err) {
    logger.error({ err }, "fp-analysis error");
    if (!res.writableEnded) res.write(`data: ${JSON.stringify({ error: "AI unavailable" })}\n\n`);
    if (!res.writableEnded) res.end();
  }
});

// ── CVSS Breakdown ────────────────────────────────────────────────────────────
router.post("/ai/cvss-breakdown/:findingId", async (req, res) => {
  const findingId = String(req.params["findingId"]);
  const cacheKey = `cvss-breakdown:${findingId}`;
  if (await serveCacheIfHit(res, cacheKey)) return;

  const abort = new AbortController();
  req.on("close", () => abort.abort());

  const session = (req as unknown as { session: { userId?: string } }).session;
  const model = await getUserModel(session.userId ?? "");

  try {
    setupSse(res);
    const hb = startSseHeartbeat(res);
    const f = await col("findings").findOne({ _id: new ObjectId(findingId) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!f) { res.write(`data: ${JSON.stringify({ done: true })}\n\n`); res.end(); clearInterval(hb); return; }

    const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
      { role: "system", content: securityExpertSystem() },
      { role: "user", content: `## CVSS Score Explanation\n\n**Vulnerability:** ${sanitize(String(f["title"]), 200)}\n**CVSS Score:** ${f["cvss_score"] ?? "N/A"}\n**CWE:** ${f["cwe_id"] ?? "N/A"}\n**Description:** ${sanitize(String(f["description"] ?? ""), 400)}\n**Endpoint:** ${sanitize(String(f["endpoint"]), 200)}\n\n## CVSS Base Score Breakdown\nExplain each metric in plain English: Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, Confidentiality, Integrity, Availability. For each: current value, what it means for this specific vulnerability, and what would change it.\n\n## Score in Context\nCompare this score to similar vulnerabilities. Is it rated correctly? Any metrics that seem off?\n\n## How to Reduce the Score\nSpecific mitigations that would lower the CVSS score (e.g., adding authentication reduces PR from N to L, which drops the score by X). Include the new score after each mitigation.\n\n## Plain-English Summary\nOne paragraph explaining this score to a developer who doesn't know CVSS.` },
    ];

    try {
      const text = await streamWithRetry(res, () => ({ model, messages, max_tokens: 1400 }), 2, abort.signal);
      if (text) { setCached(cacheKey, text).catch(() => {}); logUsage("cvss-breakdown", findingId, text); }
    } finally { clearInterval(hb); if (!res.writableEnded) res.end(); }
  } catch (err) {
    logger.error({ err }, "cvss-breakdown error");
    if (!res.writableEnded) res.write(`data: ${JSON.stringify({ error: "AI unavailable" })}\n\n`);
    if (!res.writableEnded) res.end();
  }
});

// ── Scan Compare Narrative ────────────────────────────────────────────────────
router.post("/ai/scan-compare/:scanId1/:scanId2", async (req, res) => {
  const { scanId1, scanId2 } = req.params;
  const cacheKey = `scan-compare:${scanId1}:${scanId2}`;
  if (await serveCacheIfHit(res, cacheKey)) return;

  const abort = new AbortController();
  req.on("close", () => abort.abort());

  const session = (req as unknown as { session: { userId?: string } }).session;
  const model = await getUserModel(session.userId ?? "");

  try {
    setupSse(res);
    const hb = startSseHeartbeat(res);

    const [scan1, scan2, findings1, findings2] = await Promise.all([
      col("scan_jobs").findOne({ _id: new ObjectId(scanId1) } as Record<string, unknown>),
      col("scan_jobs").findOne({ _id: new ObjectId(scanId2) } as Record<string, unknown>),
      col("findings").find({ scan_job_id: new ObjectId(scanId1) } as Record<string, unknown>).toArray() as Promise<Array<Record<string, unknown>>>,
      col("findings").find({ scan_job_id: new ObjectId(scanId2) } as Record<string, unknown>).toArray() as Promise<Array<Record<string, unknown>>>,
    ]);

    if (!scan1 || !scan2) { res.write(`data: ${JSON.stringify({ error: "One or both scans not found" })}\n\n`); res.end(); clearInterval(hb); return; }

    const set1 = new Set(findings1.map(f => sanitize(String(f["title"]), 100)));
    const set2 = new Set(findings2.map(f => sanitize(String(f["title"]), 100)));
    const newFindings = findings2.filter(f => !set1.has(sanitize(String(f["title"]), 100)));
    const fixedFindings = findings1.filter(f => !set2.has(sanitize(String(f["title"]), 100)));
    const recurring = findings2.filter(f => set1.has(sanitize(String(f["title"]), 100)));

    const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
      { role: "system", content: securityExpertSystem() },
      { role: "user", content: `## Scan Comparison Analysis\n\n**Scan A (baseline):** ${scan1.target_url} | Risk: ${scan1.risk_score}/100 | ${findings1.length} findings\n**Scan B (current):** ${scan2.target_url} | Risk: ${scan2.risk_score}/100 | ${findings2.length} findings\n\n**New findings (introduced):** ${newFindings.length}\n${newFindings.slice(0, 6).map(f => `- [${String(f["severity"]).toUpperCase()}] ${sanitize(String(f["title"]), 100)}`).join("\n") || "None"}\n\n**Fixed findings (resolved):** ${fixedFindings.length}\n${fixedFindings.slice(0, 6).map(f => `- ${sanitize(String(f["title"]), 100)}`).join("\n") || "None"}\n\n**Recurring findings (persisting):** ${recurring.length}\n\nWrite a comparison report:\n\n## Risk Trend\nDid security improve or degrade? By how much? What drove the change?\n\n## New Vulnerabilities Introduced\nFor each new critical/high finding: where did it likely come from (new feature, dependency update, config change)?\n\n## Remediation Progress\nCredit for fixes. Are the right things being prioritized?\n\n## Persistent Issues\nFindings that appear in both scans are technical debt. What does their persistence suggest about engineering practices?\n\n## Recommendations\nSpecific actions for the next sprint based on this comparison.` },
    ];

    try {
      const text = await streamWithRetry(res, () => ({ model, messages, max_tokens: 1800 }), 2, abort.signal);
      if (text) { setCached(cacheKey, text).catch(() => {}); logUsage("scan-compare", scanId1, text); }
    } finally { clearInterval(hb); if (!res.writableEnded) res.end(); }
  } catch (err) {
    logger.error({ err }, "scan-compare error");
    if (!res.writableEnded) res.write(`data: ${JSON.stringify({ error: "AI unavailable" })}\n\n`);
    if (!res.writableEnded) res.end();
  }
});

// ── AI Deduplication ──────────────────────────────────────────────────────────
router.post("/ai/deduplicate/:scanId", async (req, res) => {
  const { scanId } = req.params;
  try {
    const findings = await col("findings").find({ scan_job_id: new ObjectId(scanId) } as Record<string, unknown>).toArray() as Array<Record<string, unknown>>;
    if (findings.length < 2) { res.json({ duplicates: [], message: "Not enough findings to compare." }); return; }

    const list = findings.map((f, idx) => `[${idx}] ${sanitize(String(f["title"]), 100)} | ${f["category"]} | ${sanitize(String(f["endpoint"]), 80)} | CWE: ${f["cwe_id"] ?? "N/A"}`).join("\n");

    const openai = await getOpenAI();
    const resp = await openai.chat.completions.create({
      model: getModel(), stream: false,
      messages: [
        { role: "system", content: "You are a security findings deduplication engine. Respond with ONLY valid JSON." },
        { role: "user", content: `Identify duplicate or near-duplicate security findings from this list. Two findings are duplicates if they describe the same vulnerability class at the same or overlapping endpoints.\n\nFindings:\n${list}\n\nRespond with ONLY this JSON structure (no markdown, no explanation):\n{"duplicates": [{"group": [0, 3], "reason": "Same SQLi at same endpoint, different parameter"}, ...]}\n\nIf no duplicates, return: {"duplicates": []}` },
      ],
      max_tokens: 800,
    });

    const text = resp.choices[0]?.message?.content ?? "{}";
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) { res.json({ duplicates: [] }); return; }

    const result = JSON.parse(jsonMatch[0]) as { duplicates: Array<{ group: number[]; reason: string }> };

    // Enrich with actual finding data
    const enriched = (result.duplicates ?? []).map(d => ({
      ...d,
      findings: d.group.map(idx => ({
        id: String(findings[idx]?.["_id"] ?? ""),
        title: String(findings[idx]?.["title"] ?? ""),
        endpoint: String(findings[idx]?.["endpoint"] ?? ""),
        severity: String(findings[idx]?.["severity"] ?? ""),
      })).filter(f => f.id),
    }));

    logUsage("deduplicate", scanId, text);
    res.json({ duplicates: enriched });
  } catch (err) {
    logger.error({ err }, "deduplicate error");
    res.status(500).json({ error: "AI unavailable" });
  }
});

// ── Autonomous Pentest Orchestrator ─────────────────────────────────────────
router.post("/ai/autonomous-pentest/:targetId", async (req, res) => {
  const { targetId } = req.params;

  try {
    let targetUrl: string;
    const target = await col("targets").findOne({ _id: new ObjectId(targetId) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (target) {
      targetUrl = (target["url"] as string) ?? (target["domain"] as string);
    } else {
      return res.status(404).json({ error: "Target not found" });
    }

    const { EventEmitter } = await import("events");
    const { AutonomousPentestAgent } = await import("../services/ai-pentest/orchestrator");

    setupSse(res);
    const hb = startSseHeartbeat(res);
    const events = new EventEmitter();

    events.on("pentest-event", (data) => {
      if (!res.writableEnded) {
        res.write(`data: ${JSON.stringify(data)}\n\n`);
      }
    });

    try {
      const agent = new AutonomousPentestAgent(targetUrl, events);
      const session = await agent.run(15);

      res.write(`data: ${JSON.stringify({
        type: "session-complete",
        session: {
          actions: session.actions.length,
          vulns: session.confirmedVulns.size,
          riskScore: session.riskScore,
          chainOfThought: session.chainOfThought.slice(-5),
        }
      })}\n\n`);

      logUsage("autonomous-pentest", targetId, JSON.stringify(session.chainOfThought.slice(-3)));
    } finally {
      clearInterval(hb);
      if (!res.writableEnded) res.end();
    }
  } catch (err) {
    logger.error({ err }, "Autonomous pentest error");
    if (!res.writableEnded) {
      res.write(`data: ${JSON.stringify({ error: "Pentest failed" })}\n\n`);
      res.end();
    }
  }
});

// ── Safe Exploit Verification ───────────────────────────────────────────────
router.post("/ai/verify-finding/:findingId", async (req, res) => {
  const findingId = String(req.params["findingId"]);
  const cacheKey = `verify:${findingId}`;
  if (await serveCacheIfHit(res, cacheKey)) return;

  const abort = new AbortController();
  req.on("close", () => abort.abort());

  try {
    setupSse(res);
    const hb = startSseHeartbeat(res);

    const { verifyFinding } = await import("../services/ai-pentest/verification");
    const result = await verifyFinding(findingId);

    const text = JSON.stringify(result, null, 2);
    setCached(cacheKey, text).catch(() => {});
    logUsage("verify-finding", findingId, text);

    if (!res.writableEnded) {
      res.write(`data: ${JSON.stringify({
        verdict: result.verdict,
        confidence: result.confidence,
        reasoning: result.reasoning,
        pocRequest: result.pocRequest,
        pocResponse: result.pocResponse,
        exploitDifficulty: result.exploitDifficulty,
        estimatedTime: result.estimatedTimeToExploit,
      })}\n\n`);
      res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
    }

    clearInterval(hb);
    if (!res.writableEnded) res.end();
  } catch (err) {
    logger.error({ err }, "Verify finding error");
    if (!res.writableEnded) {
      res.write(`data: ${JSON.stringify({ error: "Verification failed" })}\n\n`);
      res.end();
    }
  }
});

// ── Enhanced Auto-Patch Generator ────────────────────────────────────────────
router.post("/ai/generate-patch/:findingId", async (req, res) => {
  const findingId = String(req.params["findingId"]);
  const { tech_stack } = req.body as { tech_stack?: string };
  const cacheKey = `generate-patch:${findingId}:${tech_stack ?? "auto"}`;
  if (await serveCacheIfHit(res, cacheKey)) return;

  const abort = new AbortController();
  req.on("close", () => abort.abort());

  try {
    setupSse(res);
    const hb = startSseHeartbeat(res);

    const { generatePatch } = await import("../services/ai-pentest/patch-generator");
    const result = await generatePatch(findingId, tech_stack);

    const text = JSON.stringify(result, null, 2);
    setCached(cacheKey, text).catch(() => {});
    logUsage("generate-patch", findingId, text);

    if (!res.writableEnded) {
      res.write(`data: ${JSON.stringify({
        vulnerableCode: result.vulnerableCode,
        patchedCode: result.patchedCode,
        diff: result.diff,
        explanation: result.explanation,
        language: result.language,
        framework: result.framework,
      })}\n\n`);
      res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
    }

    clearInterval(hb);
    if (!res.writableEnded) res.end();
  } catch (err) {
    logger.error({ err }, "Generate patch error");
    if (!res.writableEnded) {
      res.write(`data: ${JSON.stringify({ error: "Patch generation failed" })}\n\n`);
      res.end();
    }
  }
});

// ── Explainable AI Reasoning Chain ───────────────────────────────────────────
router.post("/ai/reasoning-chain/:findingId", async (req, res) => {
  const findingId = String(req.params["findingId"]);
  const cacheKey = `reasoning:${findingId}`;
  if (await serveCacheIfHit(res, cacheKey)) return;

  const abort = new AbortController();
  req.on("close", () => abort.abort());

  try {
    setupSse(res);
    const hb = startSseHeartbeat(res);

    const { generateReasoningChain } = await import("../services/ai-pentest/reasoning-chain");
    const result = await generateReasoningChain(findingId);

    const text = JSON.stringify(result, null, 2);
    setCached(cacheKey, text).catch(() => {});
    logUsage("reasoning-chain", findingId, text);

    if (!res.writableEnded) {
      res.write(`data: ${JSON.stringify({
        steps: result.steps,
        attackPath: result.attackPath,
        mitreTtps: result.mitreTtps,
        rootCause: result.rootCause,
        fixComplexity: result.fixComplexity,
        estimatedFixTime: result.estimatedFixTime,
        businessImpact: result.businessImpact,
        similarCves: result.similarCves,
        preventionPattern: result.preventionPattern,
      })}\n\n`);
      res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
    }

    clearInterval(hb);
    if (!res.writableEnded) res.end();
  } catch (err) {
    logger.error({ err }, "Reasoning chain error");
    if (!res.writableEnded) {
      res.write(`data: ${JSON.stringify({ error: "Reasoning analysis failed" })}\n\n`);
      res.end();
    }
  }
});

// POST /ai/code-fix/:findingId — REST (non-streaming) code patch via ai-remediation service
router.post("/ai/code-fix/:findingId", requireAuth, async (req, res) => {
  const findingId = String(req.params["findingId"]);
  if (!ObjectId.isValid(findingId)) return res.status(404).json({ error: "Not found" });
  try {
    const finding = await col("findings").findOne({ _id: new ObjectId(findingId) } as Record<string, unknown>) as Record<string, unknown> | null;
    if (!finding) return res.status(404).json({ error: "Finding not found" });

    const { generateCodePatch } = await import("../services/ai-remediation");
    const patch = await generateCodePatch(finding as never);
    if (!patch) return res.status(503).json({ error: "AI remediation unavailable — configure OPENCODE_API_KEY or OPENAI_API_KEY" });

    res.json(patch);
  } catch (err) {
    logger.error({ err }, "Code fix error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Feedback Stats ────────────────────────────────────────────────────────────
router.get("/ai/feedback/stats", async (_req, res) => {
  try {
    const stats = await col("ai_feedback").aggregate([
      { $group: { _id: { type: "$type", vote: "$vote" }, count: { $sum: 1 } } }
    ]).toArray() as Array<Record<string, unknown>>;

    let total = 0;
    let positive = 0;
    let negative = 0;
    const by_type: Record<string, { positive: number; negative: number }> = {};

    for (const entry of stats) {
      const id = entry["_id"] as { type?: string; vote?: string };
      const count = Number(entry["count"] ?? 0);
      const type = String(id?.type ?? "unknown");
      const vote = String(id?.vote ?? "");

      total += count;
      if (vote === "up" || vote === "positive") positive += count;
      else if (vote === "down" || vote === "negative") negative += count;

      if (!by_type[type]) by_type[type] = { positive: 0, negative: 0 };
      if (vote === "up" || vote === "positive") by_type[type].positive += count;
      else if (vote === "down" || vote === "negative") by_type[type].negative += count;
    }

    const accuracy_rate = total > 0 ? `${Math.round((positive / total) * 100)}%` : "N/A";
    res.json({ total, positive, negative, by_type, accuracy_rate });
  } catch (err) {
    logger.error({ err }, "Feedback stats error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
