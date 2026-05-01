import { ScanContext, ScanFinding, safeFetch } from "./types";

// Server-Side Template Injection payloads
const SSTI_PROBES = [
  { payload: "{{7*7}}", marker: "49", engine: "Jinja2/Twig" },
  { payload: "${7*7}", marker: "49", engine: "FreeMarker/Thymeleaf" },
  { payload: "<%= 7*7 %>", marker: "49", engine: "ERB/EJS" },
  { payload: "#{7*7}", marker: "49", engine: "Ruby/Pebble" },
  { payload: "*{7*7}", marker: "49", engine: "Spring Expression" },
  { payload: "{{7*'7'}}", marker: "7777777", engine: "Jinja2" },
];

// CRLF Injection payloads
const CRLF_PROBES = [
  "%0d%0aX-Injected-Header: crlf-test",
  "%0d%0a%0d%0a<script>crlf</script>",
  "\r\nX-Injected: crlf",
  "%E5%98%8A%E5%98%8DX-Injected: crlf",
];

// Prototype pollution probes
const PROTO_PROBES = [
  { payload: { "__proto__": { "isAdmin": true } }, check: "isAdmin" },
  { payload: { "constructor": { "prototype": { "isAdmin": true } } }, check: "isAdmin" },
  { payload: { "__proto__[isAdmin]": "true" }, check: "isAdmin" },
];

const TEST_PARAMS = ["q", "search", "template", "view", "name", "input", "data", "message", "text"];

export async function runSstiCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints, profile } = ctx;
  const findings: ScanFinding[] = [];
  const seen = new Set<string>();

  emit({ type: "engine_start", engine: "SSTI Scanner", message: "Probing for Server-Side Template Injection" });

  const budget = profile === "quick" ? 2 : profile === "standard" ? 4 : 8;
  const endpoints = discoveredEndpoints.slice(0, budget);

  for (const endpoint of endpoints) {
    for (const probe of SSTI_PROBES.slice(0, 3)) {
      for (const param of TEST_PARAMS.slice(0, 4)) {
        const testUrl = `${endpoint}${endpoint.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(probe.payload)}`;
        const res = await safeFetch(testUrl);
        if (!res) continue;

        const body = await res.text().catch(() => "");
        if (body.includes(probe.marker)) {
          const key = `${endpoint}:ssti`;
          if (seen.has(key)) continue;
          seen.add(key);

          findings.push({
            title: `Server-Side Template Injection (${probe.engine})`,
            category: "Template Injection",
            severity: "critical",
            endpoint,
            description: `The parameter "${param}" is vulnerable to Server-Side Template Injection using ${probe.engine} syntax. The expression ${probe.payload} was evaluated server-side, returning ${probe.marker}. This can lead to Remote Code Execution.`,
            evidence: `GET ${testUrl}\nPayload: ${probe.payload}\nExpected: ${probe.marker}\nBody response contained evaluation result`,
            recommended_fix: "Never pass user input directly to a template engine. Use a sandboxed environment or disable expression evaluation for user-controlled inputs.",
            cvss_score: 9.8,
            cwe_id: "CWE-94",
            scanner_name: "SSTI Scanner",
            scanner_family: "web",
            confidence: 0.92,
          });
          emit({ type: "log", message: `  [SSTI] ${probe.engine} injection at ${endpoint} param=${param}` });
          break;
        }
      }
    }
  }

  if (findings.length === 0) emit({ type: "log", message: "No SSTI vulnerabilities detected" });
  emit({ type: "engine_done", engine: "SSTI Scanner", message: `SSTI check complete — ${findings.length} issue(s)` });
  return findings;
}

export async function runCrlfCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints, profile } = ctx;
  const findings: ScanFinding[] = [];
  const seen = new Set<string>();

  emit({ type: "engine_start", engine: "CRLF Scanner", message: "Testing for CRLF/Header injection" });

  const budget = profile === "quick" ? 2 : 5;
  const params = ["url", "redirect", "next", "return", "location", "path"];

  for (const endpoint of discoveredEndpoints.slice(0, budget)) {
    for (const probe of CRLF_PROBES.slice(0, 2)) {
      for (const param of params.slice(0, 3)) {
        const testUrl = `${endpoint}${endpoint.includes("?") ? "&" : "?"}${param}=${probe}`;
        const res = await safeFetch(testUrl, { redirect: "manual" });
        if (!res) continue;

        const hasInjectedHeader = res.headers.get("x-injected-header") || res.headers.get("x-injected");
        const body = await res.text().catch(() => "");
        const hasCrlfInBody = body.toLowerCase().includes("crlf") || body.includes("x-injected");

        if (hasInjectedHeader || hasCrlfInBody) {
          const key = `${endpoint}:crlf`;
          if (seen.has(key)) continue;
          seen.add(key);

          findings.push({
            title: `CRLF Injection / HTTP Header Injection: ${param}`,
            category: "Header Injection",
            severity: "high",
            endpoint,
            description: `The "${param}" parameter allows injecting arbitrary HTTP headers via CRLF sequences. Attackers can add arbitrary response headers, enabling cache poisoning, XSS, and session fixation.`,
            evidence: `GET ${testUrl}\nCRLF payload: ${probe}\nInjected header found: ${hasInjectedHeader ?? "in body"}`,
            recommended_fix: "Strip or reject CRLF characters (\\r\\n) from all URL parameters used in HTTP responses. Encode output when inserting user input into headers.",
            cvss_score: 6.1,
            cwe_id: "CWE-113",
            scanner_name: "CRLF Scanner",
            scanner_family: "web",
            confidence: 0.9,
          });
          emit({ type: "log", message: `  [CRLF] Header injection at ${endpoint} param=${param}` });
          break;
        }
      }
    }
  }

  if (findings.length === 0) emit({ type: "log", message: "No CRLF injection detected" });
  emit({ type: "engine_done", engine: "CRLF Scanner", message: `CRLF check complete — ${findings.length} issue(s)` });
  return findings;
}

export async function runPrototypePollutionCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Prototype Pollution", message: "Testing for prototype pollution vectors" });

  const apiEndpoints = discoveredEndpoints.filter(ep => ep.includes("/api")).slice(0, 5);

  for (const endpoint of apiEndpoints) {
    for (const probe of PROTO_PROBES.slice(0, 2)) {
      const res = await safeFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(probe.payload),
      });

      if (!res) continue;
      const body = await res.text().catch(() => "");

      if (body.includes(probe.check) || res.status === 200) {
        // Follow up with a GET to check if the prototype was polluted
        const checkRes = await safeFetch(endpoint);
        if (checkRes) {
          const checkBody = await checkRes.text().catch(() => "");
          if (checkBody.includes(probe.check)) {
            findings.push({
              title: "Prototype Pollution in API Endpoint",
              category: "Injection",
              severity: "high",
              endpoint,
              description: "The API endpoint accepts JSON payloads containing __proto__ or constructor.prototype keys, which can pollute the JavaScript prototype chain and affect all objects in the application.",
              evidence: `POST ${endpoint}\nPayload: ${JSON.stringify(probe.payload)}\nCheck field "${probe.check}" found in subsequent response`,
              recommended_fix: "Sanitize JSON input to reject __proto__, constructor, and prototype keys. Use Object.create(null) for objects used as maps. Apply a JSON schema validator that explicitly forbids prototype pollution payloads.",
              cvss_score: 7.5,
              cwe_id: "CWE-1321",
              scanner_name: "Prototype Pollution",
              scanner_family: "web",
              confidence: 0.75,
            });
            emit({ type: "log", message: `  [PROTO] Prototype pollution at ${endpoint}` });
            break;
          }
        }
      }
    }
  }

  if (findings.length === 0) emit({ type: "log", message: "No prototype pollution detected" });
  emit({ type: "engine_done", engine: "Prototype Pollution", message: `Prototype pollution check complete — ${findings.length} issue(s)` });
  return findings;
}
