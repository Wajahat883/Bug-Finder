import { ScanContext, ScanFinding } from "./types";

const ZAP_URL = process.env["ZAP_URL"] ?? "http://zap:8080";
const ZAP_API = `${ZAP_URL}/JSON`;

async function zapGet(path: string): Promise<Record<string, unknown>> {
  try {
    const res = await fetch(`${ZAP_API}/${path}`, { signal: AbortSignal.timeout(15000) });
    if (!res.ok) return {};
    return await res.json() as Record<string, unknown>;
  } catch {
    return {};
  }
}

async function waitForSpider(scanId: string, maxWait = 120000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < maxWait) {
    const status = await zapGet(`spider/view/status/?scanId=${scanId}`);
    if (Number(status["status"]) >= 100) return;
    await new Promise((r) => setTimeout(r, 2000));
  }
}

async function waitForActiveScan(scanId: string, maxWait = 300000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < maxWait) {
    const status = await zapGet(`ascan/view/status/?scanId=${scanId}`);
    if (Number(status["status"]) >= 100) return;
    await new Promise((r) => setTimeout(r, 3000));
  }
}

const ZAP_RISK_MAP: Record<string, "critical" | "high" | "medium" | "low" | "info"> = {
  "3": "high",
  "2": "medium",
  "1": "low",
  "0": "info",
};

const ZAP_CVSS_MAP: Record<string, number> = {
  "3": 7.5,
  "2": 5.0,
  "1": 3.1,
  "0": 0.0,
};

function zapAlertToFinding(alert: Record<string, unknown>, targetUrl: string): ScanFinding {
  const risk = String(alert["riskcode"] ?? "0");
  const severity = ZAP_RISK_MAP[risk] ?? "info";

  return {
    title: String(alert["name"] ?? "Unknown Finding"),
    category: String(alert["tags"] ? "Web Application" : "Web Application"),
    severity,
    endpoint: String(alert["url"] ?? targetUrl),
    description: String(alert["description"] ?? ""),
    evidence: alert["evidence"] ? String(alert["evidence"]) : `ZAP alert at ${String(alert["url"] ?? targetUrl)}`,
    recommended_fix: String(alert["solution"] ?? "Apply vendor-recommended security patches."),
    cvss_score: ZAP_CVSS_MAP[risk] ?? 0,
    cwe_id: alert["cweid"] ? `CWE-${alert["cweid"]}` : "CWE-200",
    scanner_name: "Bug-Finder/ZAP",
    scanner_family: "active",
    confidence: risk === "3" ? 0.90 : risk === "2" ? 0.75 : 0.60,
  };
}

export async function runZapScan(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, profile } = ctx;

  emit({ type: "engine_start", engine: "Bug-Finder/ZAP", message: "Starting OWASP ZAP active scan" });

  // Check ZAP is reachable
  const version = await zapGet("core/view/version/");
  if (!version["version"]) {
    emit({ type: "log", message: "ZAP not reachable — skipping active scan" });
    return [];
  }

  emit({ type: "log", message: `ZAP ${version["version"]} connected` });

  // Spider the target first
  emit({ type: "log", message: `Spidering ${targetUrl}...` });
  const spiderResp = await zapGet(`spider/action/scan/?url=${encodeURIComponent(targetUrl)}&maxChildren=10&recurse=true`);
  const spiderId = String(spiderResp["scan"] ?? "");
  if (spiderId) await waitForSpider(spiderId, 60000);

  emit({ type: "log", message: "Spider complete — starting active scan" });

  // Active scan (skip for quick profile — only passive)
  if (profile !== "quick") {
    const scanStrength = profile === "deep" ? "HIGH" : "MEDIUM";
    const ascanResp = await zapGet(
      `ascan/action/scan/?url=${encodeURIComponent(targetUrl)}&recurse=true&scanPolicyName=&method=GET&postData=&contextId=&strength=${scanStrength}`
    );
    const ascanId = String(ascanResp["scan"] ?? "");
    if (ascanId) {
      const maxWait = profile === "deep" ? 300000 : 120000;
      await waitForActiveScan(ascanId, maxWait);
      emit({ type: "log", message: "Active scan complete" });
    }
  }

  // Retrieve alerts
  const alertsResp = await zapGet(`core/view/alerts/?baseurl=${encodeURIComponent(targetUrl)}&start=0&count=200`);
  const alerts = (alertsResp["alerts"] as Record<string, unknown>[] | undefined) ?? [];

  // Deduplicate by name+url
  const seen = new Set<string>();
  const findings: ScanFinding[] = [];
  for (const alert of alerts) {
    const key = `${alert["name"]}|${alert["url"]}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push(zapAlertToFinding(alert, targetUrl));
  }

  emit({ type: "log", message: `ZAP found ${findings.length} alerts` });

  // Clean up ZAP session
  await zapGet("core/action/deleteAllAlerts/");

  return findings;
}
