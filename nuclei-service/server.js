"use strict";

const express = require("express");
const { spawn, execSync } = require("child_process");
const { randomUUID } = require("crypto");

const app = express();
app.use(express.json({ limit: "1mb" }));

const PORT = parseInt(process.env.PORT ?? "8088", 10);
const TEMPLATES_DIR = process.env.NUCLEI_TEMPLATES_DIR ?? "/home/nuclei/nuclei-templates";
const NUCLEI_BINARY = process.env.NUCLEI_BINARY ?? "nuclei";
const MAX_CONCURRENT = parseInt(process.env.MAX_CONCURRENT_SCANS ?? "3", 10);

let activeScans = 0;

// ── Startup: ensure templates are fresh ──────────────────────────────────────
function updateTemplates() {
  try {
    execSync(`${NUCLEI_BINARY} -update-templates -ud ${TEMPLATES_DIR}`, {
      stdio: "pipe",
      timeout: 120000,
    });
    console.log("[nuclei-service] Templates updated successfully");
  } catch (err) {
    console.warn("[nuclei-service] Template update failed (non-fatal):", err.message);
  }
}

// ── JSONL parser ──────────────────────────────────────────────────────────────
function parseJsonl(line) {
  if (!line.trim() || !line.startsWith("{")) return null;
  try {
    const r = JSON.parse(line);
    const info = r.info ?? {};
    const classification = info.classification ?? {};
    const sev = String(info.severity ?? r.severity ?? "info").toLowerCase();
    const validSev = ["critical", "high", "medium", "low", "info"].includes(sev) ? sev : "info";
    return {
      "template-id": r["template-id"] ?? "unknown",
      name: info.name ?? r["template-id"] ?? "Nuclei Finding",
      severity: validSev,
      "matched-at": r["matched-at"] ?? "",
      description: info.description ?? "",
      remediation: info.remediation ?? "",
      tags: Array.isArray(info.tags) ? info.tags.join(",") : (info.tags ?? ""),
      "cwe-id": classification["cwe-id"] ?? "CWE-200",
      "cvss-score": typeof r["cvss-score"] === "number" ? r["cvss-score"] : null,
      "extracted-results": r["extracted-results"] ?? null,
      "curl-command": r["curl-command"] ?? null,
      type: r.type ?? "http",
      host: r.host ?? "",
      "matcher-name": r["matcher-name"] ?? "",
    };
  } catch {
    return null;
  }
}

// ── Build nuclei args ─────────────────────────────────────────────────────────
function buildArgs(target, options = {}) {
  const {
    templates = ["cves", "exposures", "misconfiguration", "vulnerabilities"],
    severity = ["critical", "high", "medium"],
    headers = {},
    timeout = 10,
    retries = 1,
    rateLimit = 150,
    maxHostErrors = 30,
  } = options;

  const args = [
    "-u", target,
    "-j",
    "-nc",
    "-silent",
    "-ud", TEMPLATES_DIR,
    "-severity", severity.join(","),
    "-timeout", String(timeout),
    "-retries", String(retries),
    "-rate-limit", String(rateLimit),
    "-max-host-error", String(maxHostErrors),
    "-no-stdin",
  ];

  // Add template categories
  for (const t of templates) {
    args.push("-t", t);
  }

  // Add auth headers
  for (const [key, value] of Object.entries(headers)) {
    args.push("-H", `${key}: ${value}`);
  }

  return args;
}

// ── POST /api/scan ────────────────────────────────────────────────────────────
app.post("/api/scan", async (req, res) => {
  if (activeScans >= MAX_CONCURRENT) {
    return res.status(429).json({
      error: "Too many concurrent scans",
      active: activeScans,
      limit: MAX_CONCURRENT,
    });
  }

  const { target, templates, severity, headers, timeout, rateLimit } = req.body ?? {};

  if (!target || typeof target !== "string") {
    return res.status(400).json({ error: "target (string) is required" });
  }

  const scanId = randomUUID();
  activeScans++;
  const startedAt = Date.now();
  console.log(`[nuclei-service] [${scanId}] Starting scan → ${target}`);

  const findings = [];
  let stderrBuf = "";

  const args = buildArgs(target, { templates, severity, headers, timeout, rateLimit });

  try {
    await new Promise((resolve, reject) => {
      const proc = spawn(NUCLEI_BINARY, args, { timeout: 300000 });

      proc.stdout.on("data", (chunk) => {
        for (const line of chunk.toString().split("\n")) {
          const f = parseJsonl(line);
          if (f) findings.push(f);
        }
      });

      proc.stderr.on("data", (chunk) => {
        stderrBuf += chunk.toString();
      });

      proc.on("close", (code) => {
        if (code !== 0 && findings.length === 0) {
          console.warn(`[nuclei-service] [${scanId}] Non-zero exit ${code}: ${stderrBuf.slice(0, 300)}`);
        }
        resolve();
      });

      proc.on("error", (err) => {
        reject(err);
      });
    });
  } catch (err) {
    activeScans--;
    console.error(`[nuclei-service] [${scanId}] Spawn error:`, err.message);
    return res.status(500).json({ error: "Nuclei spawn failed", detail: err.message });
  }

  activeScans--;
  const duration = Date.now() - startedAt;
  console.log(`[nuclei-service] [${scanId}] Done — ${findings.length} finding(s) in ${duration}ms`);

  return res.json({
    scanId,
    target,
    duration,
    count: findings.length,
    results: findings,
  });
});

// ── POST /api/scan/stream (SSE streaming for long scans) ──────────────────────
app.post("/api/scan/stream", async (req, res) => {
  if (activeScans >= MAX_CONCURRENT) {
    return res.status(429).json({ error: "Too many concurrent scans" });
  }

  const { target, templates, severity, headers, timeout, rateLimit } = req.body ?? {};
  if (!target) return res.status(400).json({ error: "target is required" });

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  const scanId = randomUUID();
  activeScans++;

  const send = (event, data) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  send("start", { scanId, target });

  const args = buildArgs(target, { templates, severity, headers, timeout, rateLimit });
  const proc = spawn(NUCLEI_BINARY, args, { timeout: 300000 });

  proc.stdout.on("data", (chunk) => {
    for (const line of chunk.toString().split("\n")) {
      const f = parseJsonl(line);
      if (f) send("finding", f);
    }
  });

  proc.on("close", (code) => {
    activeScans--;
    send("done", { scanId, exitCode: code });
    res.end();
  });

  proc.on("error", (err) => {
    activeScans--;
    send("error", { message: err.message });
    res.end();
  });

  req.on("close", () => {
    proc.kill("SIGTERM");
  });
});

// ── GET /api/templates — list available template categories ──────────────────
app.get("/api/templates", (_req, res) => {
  try {
    const output = execSync(
      `${NUCLEI_BINARY} -ud ${TEMPLATES_DIR} -list-templates 2>/dev/null | head -100`,
      { encoding: "utf8", timeout: 10000 }
    );
    const templates = output.split("\n").filter(Boolean);
    res.json({ count: templates.length, templates: templates.slice(0, 100) });
  } catch {
    res.json({ count: 0, templates: [] });
  }
});

// ── GET /health ───────────────────────────────────────────────────────────────
app.get("/health", (_req, res) => {
  let nucleiVersion = "unknown";
  try {
    nucleiVersion = execSync(`${NUCLEI_BINARY} -version 2>&1`, {
      encoding: "utf8",
      timeout: 5000,
    }).trim().split("\n")[0];
  } catch { /* non-fatal */ }

  res.json({
    status: "ok",
    nucleiVersion,
    activeScans,
    maxConcurrent: MAX_CONCURRENT,
    templatesDir: TEMPLATES_DIR,
    uptime: process.uptime(),
  });
});

// ── GET /metrics — Prometheus-compatible metrics ──────────────────────────────
app.get("/metrics", (_req, res) => {
  res.set("Content-Type", "text/plain");
  res.send([
    `# HELP nuclei_active_scans Number of active scans`,
    `# TYPE nuclei_active_scans gauge`,
    `nuclei_active_scans ${activeScans}`,
    `# HELP nuclei_max_concurrent_scans Max concurrent scan limit`,
    `# TYPE nuclei_max_concurrent_scans gauge`,
    `nuclei_max_concurrent_scans ${MAX_CONCURRENT}`,
    `# HELP process_uptime_seconds Process uptime`,
    `# TYPE process_uptime_seconds counter`,
    `process_uptime_seconds ${process.uptime().toFixed(2)}`,
  ].join("\n"));
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, "0.0.0.0", () => {
  console.log(`[nuclei-service] Listening on :${PORT}`);
  console.log(`[nuclei-service] Templates dir: ${TEMPLATES_DIR}`);
  console.log(`[nuclei-service] Max concurrent scans: ${MAX_CONCURRENT}`);
  // Async template update after startup — non-blocking
  setTimeout(updateTemplates, 5000);
});
