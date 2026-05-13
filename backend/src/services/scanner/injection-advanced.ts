import { ScanContext, ScanFinding, ctxFetch } from "./types";

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

  emit({ type: "engine_start", engine: "Bug-Finder/SSTI", message: "Probing for Server-Side Template Injection" });

  const budget = profile === "quick" ? 2 : profile === "standard" ? 4 : 8;
  const endpoints = discoveredEndpoints.slice(0, budget);

  // Confirmation probe pairs: both must evaluate for a confirmed finding.
  // Using two distinct expressions eliminates false positives from "49" appearing
  // in CSS, viewport meta tags, timestamps, or static page content.
  const SSTI_CONFIRM_PROBES: Array<{ payload: string; marker: string; engine: string }> = [
    { payload: "{{3*3}}", marker: "9", engine: "Jinja2/Twig" },
    { payload: "${3*3}", marker: "9", engine: "FreeMarker/Thymeleaf" },
    { payload: "<%= 3*3 %>", marker: "9", engine: "ERB/EJS" },
    { payload: "#{3*3}", marker: "9", engine: "Ruby/Pebble" },
    { payload: "*{3*3}", marker: "9", engine: "Spring Expression" },
    { payload: "{{3*'3'}}", marker: "333", engine: "Jinja2" },
  ];

  for (const endpoint of endpoints) {
    for (let i = 0; i < Math.min(3, SSTI_PROBES.length); i++) {
      const probe = SSTI_PROBES[i]!;
      const confirmProbe = SSTI_CONFIRM_PROBES[i]!;
      for (const param of TEST_PARAMS.slice(0, 4)) {
        const testUrl = `${endpoint}${endpoint.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(probe.payload)}`;
        const res = await ctxFetch(ctx, testUrl);
        if (!res) continue;

        const body = await res.text().catch(() => "");
        if (!body.includes(probe.marker)) continue;

        // ── Baseline check: "49" must NOT appear on the page without payload ──
        const baselineRes = await ctxFetch(ctx, endpoint);
        const baselineBody = baselineRes ? await baselineRes.text().catch(() => "") : "";
        if (baselineBody.includes(probe.marker)) {
          emit({ type: "log", message: `  SSTI marker "${probe.marker}" in baseline — not a finding at ${endpoint} [${param}]` });
          continue;
        }

        // ── Confirmation probe: send a DIFFERENT expression, verify it also evaluates ──
        const confirmUrl = `${endpoint}${endpoint.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(confirmProbe.payload)}`;
        const confirmRes = await ctxFetch(ctx, confirmUrl);
        const confirmBody = confirmRes ? await confirmRes.text().catch(() => "") : "";

        if (!confirmBody.includes(confirmProbe.marker) || baselineBody.includes(confirmProbe.marker)) {
          emit({ type: "log", message: `  SSTI confirmation failed at ${endpoint} [${param}] — likely static content, not execution` });
          continue;
        }

        const key = `${endpoint}:ssti`;
        if (seen.has(key)) continue;
        seen.add(key);

        const offset = body.indexOf(probe.marker);
        const snippet = body.slice(Math.max(0, offset - 80), offset + 80);

        findings.push({
          title: `Server-Side Template Injection (${probe.engine})`,
          category: "Template Injection",
          severity: "critical",
          endpoint,
          description: `Parameter "${param}" is confirmed vulnerable to Server-Side Template Injection using ${probe.engine} syntax. Two independent mathematical expressions were evaluated server-side: "${probe.payload}" → "${probe.marker}" AND "${confirmProbe.payload}" → "${confirmProbe.marker}". Neither result appears in the baseline response. This confirms template execution and can lead to Remote Code Execution.`,
          evidence: [
            `Probe 1: GET ${testUrl}`,
            `  Expression: ${probe.payload} → Expected: ${probe.marker} → Found: YES (offset ${offset})`,
            `  Context: ...${snippet}...`,
            ``,
            `Probe 2: GET ${confirmUrl}`,
            `  Expression: ${confirmProbe.payload} → Expected: ${confirmProbe.marker} → Found: YES`,
            ``,
            `Baseline: GET ${endpoint}`,
            `  Neither marker present in baseline response — execution confirmed, not static content`,
          ].join("\n"),
          recommended_fix: "Never pass user input directly to a template engine. Sandbox the template context. Disable expression evaluation for untrusted inputs. Switch to logic-less templates (Mustache, Handlebars with no helpers) for user-facing content.",
          cvss_score: 9.8,
          cwe_id: "CWE-94",
          scanner_name: "Bug-Finder/SSTI",
          scanner_family: "web",
          confidence: 0.97,
        });
        emit({ type: "log", message: `  [SSTI CONFIRMED] ${probe.engine} dual-probe confirmed at ${endpoint} param=${param}` });
        break;
      }
    }
  }

  if (findings.length === 0) emit({ type: "log", message: "No SSTI vulnerabilities detected" });
  emit({ type: "engine_done", engine: "Bug-Finder/SSTI", message: `SSTI check complete — ${findings.length} issue(s)` });
  return findings;
}

export async function runCrlfCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints, profile } = ctx;
  const findings: ScanFinding[] = [];
  const seen = new Set<string>();

  emit({ type: "engine_start", engine: "Bug-Finder/CRLF", message: "Testing for CRLF/Header injection" });

  const budget = profile === "quick" ? 2 : 5;
  const params = ["url", "redirect", "next", "return", "location", "path"];

  for (const endpoint of discoveredEndpoints.slice(0, budget)) {
    for (const probe of CRLF_PROBES.slice(0, 2)) {
      for (const param of params.slice(0, 3)) {
        const testUrl = `${endpoint}${endpoint.includes("?") ? "&" : "?"}${param}=${probe}`;
        const res = await ctxFetch(ctx, testUrl, { redirect: "manual" });
        if (!res) continue;

        const hasInjectedHeader = res.headers.get("x-injected-header") || res.headers.get("x-injected");
        const body = await res.text().catch(() => "");

        // Only confirm via injected header — body text check ("crlf", "x-injected") would fire
        // on documentation pages or error messages that mention CRLF injection.
        if (hasInjectedHeader) {
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
            scanner_name: "Bug-Finder/CRLF",
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
  emit({ type: "engine_done", engine: "Bug-Finder/CRLF", message: `CRLF check complete — ${findings.length} issue(s)` });
  return findings;
}

export async function runPrototypePollutionCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Bug-Finder/ProtoPollution", message: "Testing for prototype pollution vectors" });

  const apiEndpoints = discoveredEndpoints.filter(ep => ep.includes("/api")).slice(0, 5);

  for (const endpoint of apiEndpoints) {
    // Baseline GET before injecting — if isAdmin:true is already present, skip to avoid false positive
    const baselineRes = await ctxFetch(ctx, endpoint);
    const baselineBody = baselineRes ? await baselineRes.text().catch(() => "") : "";
    if (/["']?isAdmin["']?\s*:\s*true/.test(baselineBody)) {
      emit({ type: "log", message: `  Proto pollution baseline contains isAdmin:true at ${endpoint} — skipping` });
      continue;
    }

    for (const probe of PROTO_PROBES.slice(0, 2)) {
      const res = await ctxFetch(ctx, endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(probe.payload),
      });

      if (!res) continue;
      const body = await res.text().catch(() => "");

      if (res.status === 200) {
        // Follow up with a GET to check if the prototype was polluted
        const checkRes = await ctxFetch(ctx, endpoint);
        if (checkRes) {
          const checkBody = await checkRes.text().catch(() => "");
          // Must see isAdmin:true — not just the string "isAdmin" (would fire on isAdmin:false)
          const polluted = /["']?isAdmin["']?\s*:\s*true/.test(checkBody);
          if (polluted) {
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
              scanner_name: "Bug-Finder/ProtoPollution",
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
  emit({ type: "engine_done", engine: "Bug-Finder/ProtoPollution", message: `Prototype pollution check complete — ${findings.length} issue(s)` });
  return findings;
}
