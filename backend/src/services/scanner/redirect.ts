import { ScanContext, ScanFinding, ctxFetch, curlReproducer } from "./types";
import { isSpaFallback } from "./spa-detector";

const REDIRECT_PARAMS = ["redirect", "redirect_uri", "redirect_url", "return", "return_url", "returnTo", "next", "url", "goto", "dest", "destination", "target", "ref", "referer", "callback", "continue"];

// Ordered by exploitability — each probe uses a distinct bypass technique
interface RedirectProbe {
  label: string;
  value: string;
  // How to detect success: check Location header contains this string
  matchIn: string;
  severity: ScanFinding["severity"];
  cvss: number;
  description: string;
}

const EVIL_HOST = "evil-redir-7f3b.example.com";

const REDIRECT_PROBES: RedirectProbe[] = [
  // Absolute URL — baseline test
  {
    label: "absolute HTTPS URL",
    value: `https://${EVIL_HOST}`,
    matchIn: EVIL_HOST,
    severity: "high",
    cvss: 6.1,
    description: "The redirect parameter accepts an absolute external URL without validation.",
  },
  // Protocol-relative — bypasses schemes-only filters
  {
    label: "protocol-relative URL (//<host>)",
    value: `//${EVIL_HOST}`,
    matchIn: EVIL_HOST,
    severity: "high",
    cvss: 6.5,
    description: "The redirect parameter accepts a protocol-relative URL (//<host>). Browsers treat this as https://<host>, so an attacker avoids scheme-based filters.",
  },
  // Backslash — some parsers normalize to forward slash, routing to external host
  {
    label: "backslash bypass (\\\\<host>)",
    value: `\\\\${EVIL_HOST}`,
    matchIn: EVIL_HOST,
    severity: "high",
    cvss: 6.5,
    description: "The server normalized a backslash-prefixed redirect value into an external URL. This bypasses validation rules that only block forward-slash paths.",
  },
  // Encoded slash — URL decoding before redirect
  {
    label: "double-encoded slash (%2F%2F<host>)",
    value: `%2F%2F${EVIL_HOST}`,
    matchIn: EVIL_HOST,
    severity: "high",
    cvss: 6.5,
    description: "The server decoded the URL before validating the redirect destination, allowing %2F%2F (double-slash) to become //<host> pointing to an external site.",
  },
  // javascript: URI — phishing / XSS via redirect
  {
    label: "javascript: URI",
    value: "javascript:alert(document.domain)",
    matchIn: "javascript:",
    severity: "high",
    cvss: 7.4,
    description: "The redirect parameter accepts a javascript: URI. Browsers will execute the payload when the user follows the link, enabling XSS via redirect.",
  },
  // data: URI — similar to javascript: for non-browser clients or older browsers
  {
    label: "data: URI",
    value: "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    matchIn: "data:",
    severity: "medium",
    cvss: 5.4,
    description: "The redirect parameter accepts a data: URI containing HTML/JS. Some browsers will render it, enabling XSS via redirect in older clients.",
  },
  // Open redirect via subdomain confusion
  {
    label: "subdomain confusion (<target>.<evil-host>)",
    value: `https://${new URL("https://placeholder").hostname}.${EVIL_HOST}`,
    matchIn: EVIL_HOST,
    severity: "medium",
    cvss: 5.4,
    description: "The redirect validation only checks that the URL starts with the target domain — an attacker can use a subdomain of the evil host that starts with the target name.",
  },
];

export async function runRedirectCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints, profile } = ctx;
  const findings: ScanFinding[] = [];
  const seen = new Set<string>();

  emit({ type: "engine_start", engine: "Bug-Finder/Redirect", message: "Testing for open redirect vulnerabilities (7 bypass techniques)" });

  const budget = profile === "quick" ? 3 : profile === "standard" ? 6 : 12;
  const base = new URL(targetUrl);

  // Fix subdomain confusion probe now that we have the real target host
  REDIRECT_PROBES[6]!.value = `https://${base.hostname}.${EVIL_HOST}`;

  const authEndpoints = [
    `${base.origin}/login`,
    `${base.origin}/logout`,
    `${base.origin}/auth`,
    `${base.origin}/oauth/authorize`,
    `${base.origin}/api/auth`,
    ...discoveredEndpoints.filter(ep => ep.includes("login") || ep.includes("auth") || ep.includes("return") || ep.includes("callback")),
  ].slice(0, budget);

  for (const endpoint of authEndpoints) {
    if (seen.has(endpoint)) continue;

    for (const param of REDIRECT_PARAMS.slice(0, 6)) {
      let foundForParam = false;

      for (const probe of REDIRECT_PROBES) {
        const testUrl = `${endpoint}${endpoint.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(probe.value)}`;
        const res = await ctxFetch(ctx, testUrl, { redirect: "manual" });
        if (!res) continue;

        const location = res.headers.get("location") ?? "";
        const isRedirect = res.status >= 300 && res.status < 400;

        // javascript:/data: URIs may not produce a 3xx — check the body too
        const body = !isRedirect ? await res.text().catch(() => "") : "";

        // Skip SPA fallback — the redirect target is the SPA shell, not a real redirect
        if (!isRedirect && isSpaFallback(res, body, ctx.spaSignature)) {
          emit({ type: "log", message: `  [SPA] Skipping redirect probe at ${endpoint} [${param}] — SPA fallback response` });
          break;
        }

        const locationOrBody = isRedirect ? location : body;

        if (locationOrBody.includes(probe.matchIn)) {
          const key = `${endpoint}:${param}:${probe.label}`;
          if (seen.has(key)) continue;
          seen.add(key);

          findings.push({
            title: `Open Redirect (${probe.label}) via param: ${param}`,
            category: "Open Redirect",
            severity: probe.severity,
            endpoint,
            description: `The "${param}" parameter at ${endpoint} is vulnerable to open redirect using the ${probe.label} technique. ${probe.description}`,
            evidence: [
              `Probe technique: ${probe.label}`,
              `Payload: ${probe.value}`,
              `GET ${testUrl}`,
              `HTTP ${res.status} ${res.statusText}`,
              isRedirect ? `Location: ${location}` : `Body matched: ${locationOrBody.slice(0, 100)}`,
            ].join("\n"),
            recommended_fix: "Validate redirect destinations against a strict allowlist of your own domains. Reject any URL that does not match — including protocol-relative (//) and javascript:. Never reflect user input into a Location header without allowlist validation.",
            cvss_score: probe.cvss,
            cwe_id: "CWE-601",
            scanner_name: "Bug-Finder/Redirect",
            scanner_family: "web",
            confidence: 0.92,
            reproduction_curl: curlReproducer("GET", testUrl),
          });
          emit({ type: "log", message: `  [Redirect] ${probe.label} via param=${param} at ${endpoint} → Location: ${location.slice(0, 60)}` });
          foundForParam = true;
          break;
        }
      }

      if (foundForParam) break;
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No open redirect vulnerabilities found" });
  }

  emit({
    type: "engine_done",
    engine: "Bug-Finder/Redirect",
    message: `Redirect check complete — ${findings.length} issue(s) found`,
  });

  return findings;
}
