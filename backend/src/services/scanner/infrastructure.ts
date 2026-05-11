import { ScanContext, ScanFinding, safeFetch } from "./types";

const WAF_SIGNATURES: Array<{ name: string; header?: string; pattern?: RegExp; cookieName?: string }> = [
  { name: "Cloudflare", header: "cf-ray" },
  { name: "Cloudflare", header: "server", pattern: /cloudflare/i },
  { name: "AWS WAF", header: "x-amzn-requestid" },
  { name: "AWS WAF", header: "x-amz-cf-id" },
  { name: "Akamai", header: "x-akamai-transformed" },
  { name: "Akamai", header: "x-check-cacheable" },
  { name: "Sucuri", header: "x-sucuri-id" },
  { name: "Imperva/Incapsula", header: "x-iinfo" },
  { name: "Imperva/Incapsula", cookieName: "visid_incap_" },
  { name: "F5 BIG-IP", header: "server", pattern: /big-ip/i },
  { name: "Barracuda", header: "server", pattern: /barracuda/i },
  { name: "ModSecurity", header: "server", pattern: /mod_security|modsecurity/i },
  { name: "Fastly", header: "x-served-by", pattern: /cache/i },
  { name: "Fastly", header: "x-fastly-request-id" },
  { name: "Varnish Cache", header: "x-varnish" },
  { name: "Nginx", header: "server", pattern: /nginx/i },
  { name: "Apache", header: "server", pattern: /apache/i },
];

export async function runInfrastructureCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "WAF/LB Detector", message: "Detecting WAF, CDN, and load balancer infrastructure" });

  const res = await safeFetch(targetUrl, { redirect: "follow" });
  if (!res) {
    emit({ type: "log", message: "Target unreachable for infrastructure check" });
    emit({ type: "engine_done", engine: "WAF/LB Detector", message: "Skipped (unreachable)" });
    return findings;
  }

  const headerDump = [...res.headers.entries()].map(([k, v]) => `${k}: ${v}`).join("\n");
  const cookies = res.headers.get("set-cookie") ?? "";

  // WAF detection
  const detectedWafs = new Set<string>();
  for (const sig of WAF_SIGNATURES) {
    if (sig.header) {
      const val = res.headers.get(sig.header);
      if (val) {
        if (!sig.pattern || sig.pattern.test(val)) {
          detectedWafs.add(sig.name);
        }
      }
    }
    if (sig.cookieName && cookies.includes(sig.cookieName)) {
      detectedWafs.add(sig.name);
    }
  }

  if (detectedWafs.size > 0) {
    const wafList = [...detectedWafs].join(", ");
    emit({ type: "log", message: `WAF/CDN detected: ${wafList}` });
    findings.push({
      title: `WAF/CDN Detected: ${wafList}`,
      category: "Infrastructure",
      severity: "info",
      endpoint: targetUrl,
      description: `The target is protected by ${wafList}. WAF bypass techniques may be required during testing. Verify that the WAF rules are up-to-date and properly configured.`,
      evidence: `Detected via response headers:\n${headerDump}`,
      recommended_fix: "Ensure WAF rules are regularly updated. Test WAF bypass resistance. Confirm WAF is configured to block common attack patterns.",
      cvss_score: 0,
      cwe_id: "CWE-693",
      scanner_name: "WAF Detector",
      scanner_family: "infrastructure",
      confidence: 0.85,
    });
  } else {
    emit({ type: "log", message: "No WAF/CDN detected — target may be unprotected" });
    findings.push({
      title: "No WAF or CDN Protection Detected",
      category: "Infrastructure",
      severity: "medium",
      endpoint: targetUrl,
      description: "No Web Application Firewall (WAF) or CDN protection was detected. The origin server may be directly exposed to the internet, increasing attack surface and DDoS risk.",
      evidence: `Response headers analyzed:\n${headerDump}\n\nNo known WAF/CDN signatures found.`,
      recommended_fix: "Consider deploying a WAF (Cloudflare, AWS WAF, ModSecurity) to filter malicious traffic and protect against common web attacks.",
      cvss_score: 5.3,
      cwe_id: "CWE-693",
      scanner_name: "WAF Detector",
      scanner_family: "infrastructure",
      confidence: 0.75,
    });
  }

  // Load balancer detection via multiple requests
  const serverHeaders: string[] = [];
  for (let i = 0; i < 3; i++) {
    const r = await safeFetch(targetUrl, { redirect: "follow" });
    if (r) {
      const s = r.headers.get("server") ?? r.headers.get("x-served-by") ?? "";
      if (s) serverHeaders.push(s);
    }
  }

  const uniqueServers = new Set(serverHeaders);
  if (uniqueServers.size > 1) {
    findings.push({
      title: "Load Balancer Detected — Multiple Backend Servers",
      category: "Infrastructure",
      severity: "info",
      endpoint: targetUrl,
      description: `Multiple distinct server identifiers were observed across requests, indicating a load balancer distributing traffic across backend nodes. Each node may have slightly different configurations.`,
      evidence: `Server headers across 3 requests:\n${serverHeaders.map((s, i) => `Request ${i + 1}: ${s}`).join("\n")}`,
      recommended_fix: "Ensure all backend nodes have identical security configurations. Test each node for vulnerabilities independently. Confirm session persistence is properly configured.",
      cvss_score: 0,
      cwe_id: "CWE-200",
      scanner_name: "LB Detector",
      scanner_family: "infrastructure",
      confidence: 0.8,
    });
    emit({ type: "log", message: `Load balancer detected: ${serverHeaders.join(" | ")}` });
  }

  // Check for origin IP disclosure
  const xRealIp = res.headers.get("x-real-ip") ?? res.headers.get("x-forwarded-for") ?? res.headers.get("x-origin-ip");
  if (xRealIp) {
    findings.push({
      title: "Origin IP Address Leaked in Response Headers",
      category: "Information Disclosure",
      severity: "medium",
      endpoint: targetUrl,
      description: `The response contains headers that may reveal the origin server's IP address (${xRealIp}). If a CDN is in use, this exposes the real origin and allows direct attack bypassing CDN/WAF protection.`,
      evidence: `Header revealing IP: ${xRealIp}`,
      recommended_fix: "Configure your CDN/proxy to strip these headers from responses. Ensure the origin IP is not disclosed in any headers, error pages, or SSL certificates.",
      cvss_score: 5.3,
      cwe_id: "CWE-200",
      scanner_name: "WAF Detector",
      scanner_family: "infrastructure",
      confidence: 0.9,
    });
    emit({ type: "log", message: `Origin IP potentially leaked: ${xRealIp}` });
  }

  emit({ type: "engine_done", engine: "WAF/LB Detector", message: `Infrastructure check complete — ${findings.length} finding(s)` });
  return findings;
}
