import { ScanContext, ScanFinding, ctxFetch } from "./types";

interface HeaderCheck {
  header: string;
  title: string;
  category: string;
  severity: ScanFinding["severity"];
  description: string;
  recommended: string;
  cvss: number;
  cwe: string;
  validator?: (value: string) => { pass: boolean; note?: string };
}

const REQUIRED_HEADERS: HeaderCheck[] = [
  {
    header: "content-security-policy",
    title: "Missing Content-Security-Policy Header",
    category: "Security Headers",
    severity: "high",
    description:
      "No Content-Security-Policy header was found. This leaves the application vulnerable to XSS and data injection attacks.",
    recommended: "Add a strict CSP: Content-Security-Policy: default-src 'self'; script-src 'self'",
    cvss: 7.4,
    cwe: "CWE-693",
  },
  {
    header: "x-frame-options",
    title: "Missing X-Frame-Options Header",
    category: "Security Headers",
    severity: "medium",
    description:
      "The X-Frame-Options header is missing. The page may be embedded in an iframe, enabling clickjacking attacks.",
    recommended: "Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN",
    cvss: 5.4,
    cwe: "CWE-1021",
  },
  {
    header: "x-content-type-options",
    title: "Missing X-Content-Type-Options Header",
    category: "Security Headers",
    severity: "low",
    description:
      "X-Content-Type-Options header is absent. Browsers may MIME-sniff responses away from the declared content-type.",
    recommended: "Add: X-Content-Type-Options: nosniff",
    cvss: 3.7,
    cwe: "CWE-693",
  },
  {
    header: "referrer-policy",
    title: "Missing Referrer-Policy Header",
    category: "Security Headers",
    severity: "low",
    description:
      "No Referrer-Policy header is set. Sensitive URL data may be sent in the Referer header to third parties.",
    recommended: "Add: Referrer-Policy: strict-origin-when-cross-origin",
    cvss: 3.1,
    cwe: "CWE-200",
  },
  {
    header: "permissions-policy",
    title: "Missing Permissions-Policy Header",
    category: "Security Headers",
    severity: "info",
    description:
      "Permissions-Policy header is not set. Browser features like camera and geolocation are not restricted.",
    recommended: "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    cvss: 2.5,
    cwe: "CWE-693",
  },
  {
    header: "x-xss-protection",
    title: "Missing or Disabled X-XSS-Protection Header",
    category: "Security Headers",
    severity: "low",
    description: "The X-XSS-Protection header is not present.",
    recommended: "Add: X-XSS-Protection: 1; mode=block (for older browsers)",
    cvss: 3.1,
    cwe: "CWE-693",
    validator: (v) => ({ pass: v.includes("1") }),
  },
];

export async function runHeaderCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Bug-Finder/Headers", message: "Analyzing HTTP security headers" });

  const res = await ctxFetch(ctx, targetUrl, { redirect: "follow" });
  if (!res) {
    emit({ type: "log", message: "Could not fetch target for header analysis" });
    emit({ type: "engine_done", engine: "Bug-Finder/Headers", message: "Header check skipped (unreachable)" });
    return findings;
  }

  const allHeaders = [...res.headers.entries()];
  const headerDump = allHeaders.map(([k, v]) => `${k}: ${v}`).join("\n");

  // Check server header leaks
  const server = res.headers.get("server");
  if (server && (server.includes("/") || /\d/.test(server))) {
    findings.push({
      title: "Server Version Disclosure via Server Header",
      category: "Information Disclosure",
      severity: "low",
      endpoint: targetUrl,
      description: `The Server header reveals software version information: "${server}".`,
      evidence: `Server: ${server}`,
      recommended_fix: "Remove or redact the Server header in your web server configuration.",
      cvss_score: 3.7,
      cwe_id: "CWE-200",
      scanner_name: "Bug-Finder/Headers",
      scanner_family: "web",
      confidence: 0.95,
    });
    emit({ type: "log", message: `Server version disclosure: ${server}` });
  }

  // Check x-powered-by header
  const poweredBy = res.headers.get("x-powered-by");
  if (poweredBy) {
    findings.push({
      title: "Technology Disclosure via X-Powered-By Header",
      category: "Information Disclosure",
      severity: "low",
      endpoint: targetUrl,
      description: `The X-Powered-By header reveals backend technology: "${poweredBy}".`,
      evidence: `X-Powered-By: ${poweredBy}`,
      recommended_fix: "Remove the X-Powered-By header (e.g., in Express: app.disable('x-powered-by')).",
      cvss_score: 3.1,
      cwe_id: "CWE-200",
      scanner_name: "Bug-Finder/Headers",
      scanner_family: "web",
      confidence: 0.95,
    });
    emit({ type: "log", message: `X-Powered-By disclosure: ${poweredBy}` });
  }

  // Check each required security header
  for (const check of REQUIRED_HEADERS) {
    const value = res.headers.get(check.header);
    let missing = !value;
    let note = "";

    if (!missing && check.validator) {
      const result = check.validator(value!);
      if (!result.pass) { missing = true; note = result.note ?? ""; }
    }

    if (missing) {
      findings.push({
        title: check.title,
        category: check.category,
        severity: check.severity,
        endpoint: targetUrl,
        description: check.description + (note ? ` (${note})` : ""),
        evidence: `Response Headers:\n${headerDump}\n\n${check.header.toUpperCase()}: [MISSING]`,
        recommended_fix: check.recommended,
        cvss_score: check.cvss,
        cwe_id: check.cwe,
        scanner_name: "Bug-Finder/Headers",
        scanner_family: "web",
        confidence: 0.95,
      });
      emit({ type: "log", message: `Missing header: ${check.header}` });
    } else {
      emit({ type: "log", message: `Header OK: ${check.header}: ${String(value).slice(0, 50)}` });
    }
  }

  emit({
    type: "engine_done",
    engine: "Bug-Finder/Headers",
    message: `Header analysis complete — ${findings.length} issue(s) found`,
  });

  return findings;
}
