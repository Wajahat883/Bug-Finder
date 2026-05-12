import { ScanContext, ScanFinding, ctxFetch, isInScope } from "./types";

// Harmless XSS markers — detect reflection without executing code
const XSS_PROBES = [
  { payload: "<xssprobe1337>", marker: "xssprobe1337", context: "html-tag" },
  { payload: `"><xsstest9871>`, marker: "xsstest9871", context: "attr-breakout" },
  { payload: `javascript:xssprobe8421`, marker: "xssprobe8421", context: "href-proto" },
  { payload: `'><xssattr8712 x='`, marker: "xssattr8712", context: "single-quote-attr" },
  { payload: `</script><xssscript1234>`, marker: "xssscript1234", context: "script-breakout" },
];

// Confirmation probes — different markers to prevent false positives
const XSS_CONFIRM_PROBES = [
  { payload: "<xssconfirm5544>", marker: "xssconfirm5544" },
  { payload: `"><xssverify3312>`, marker: "xssverify3312" },
];

const PARAM_NAMES = ["q", "search", "query", "id", "s", "input", "term", "name", "value", "redirect", "url", "keyword", "filter", "text", "msg", "message"];

export async function runXssCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints, profile } = ctx;
  const findings: ScanFinding[] = [];
  const seen = new Set<string>();

  emit({ type: "engine_start", engine: "OWASP ZAP/XSS", message: "Probing for reflected XSS vectors" });

  const budget = profile === "quick" ? 3 : profile === "standard" ? 8 : 15;
  const endpoints = discoveredEndpoints
    .filter(ep => isInScope(ctx, ep))
    .slice(0, budget);

  for (const endpoint of endpoints) {
    const paramBudget = profile === "quick" ? 3 : profile === "standard" ? 6 : PARAM_NAMES.length;
    for (const paramName of PARAM_NAMES.slice(0, paramBudget)) {
      for (const probe of XSS_PROBES.slice(0, 3)) {
        const testUrl = buildUrl(endpoint, paramName, probe.payload);
        const res = await ctxFetch(ctx, testUrl, { redirect: "follow" });
        if (!res) continue;

        const ct = res.headers.get("content-type") ?? "";
        if (!ct.includes("html") && !ct.includes("text") && !ct.includes("json")) continue;

        const body = await res.text().catch(() => "");
        if (!body.includes(probe.marker)) continue;

        // Skip if marker is HTML-entity encoded (safe reflection)
        const encodedMarker = probe.marker.replace(/</g, "&lt;").replace(/>/g, "&gt;");
        if (body.includes(encodedMarker) && !body.includes(`<${probe.marker.replace(/[<>]/g, "")}`)) {
          emit({ type: "log", message: `  XSS reflected but encoded at ${endpoint} [${paramName}] — not vulnerable` });
          continue;
        }

        const key = `${endpoint}:${paramName}`;
        if (seen.has(key)) continue;

        // ── Confirmation step: send a DIFFERENT marker to rule out static reflection ──
        const confirmProbe = XSS_CONFIRM_PROBES[0]!;
        const confirmUrl = buildUrl(endpoint, paramName, confirmProbe.payload);
        const confirmRes = await ctxFetch(ctx, confirmUrl, { redirect: "follow" });
        const confirmBody = confirmRes ? await confirmRes.text().catch(() => "") : "";

        if (!confirmBody.includes(confirmProbe.marker)) {
          // First marker appeared but confirmation marker doesn't — likely static page content, not true reflection
          emit({ type: "log", message: `  XSS false positive filtered at ${endpoint} [${paramName}] — confirmation failed` });
          continue;
        }

        // Also check: baseline response should NOT already contain the marker
        const baselineRes = await ctxFetch(ctx, endpoint, { redirect: "follow" });
        const baselineBody = baselineRes ? await baselineRes.text().catch(() => "") : "";
        if (baselineBody.includes(probe.marker)) {
          emit({ type: "log", message: `  XSS marker in baseline — skipping ${endpoint} [${paramName}]` });
          continue;
        }

        seen.add(key);

        const offset = body.indexOf(probe.marker);
        const snippet = body.slice(Math.max(0, offset - 120), offset + 120);

        findings.push({
          title: `Reflected XSS in Parameter: ${paramName}`,
          category: "XSS",
          severity: "high",
          endpoint,
          description: `Parameter "${paramName}" reflects unsanitized user input directly into the HTML response. Confirmed with two independent probes. An attacker can craft a malicious URL that executes arbitrary JavaScript in the victim's browser when clicked.`,
          evidence: [
            `GET ${testUrl}`,
            `Payload: ${probe.payload}`,
            `Marker reflected unencoded at byte offset ${offset}`,
            `\nContext:\n${snippet}`,
            `\nConfirmation: GET ${confirmUrl}`,
            `Confirmation marker "${confirmProbe.marker}" also reflected`,
          ].join("\n"),
          recommended_fix: "HTML-encode all user input before rendering: use escapeHtml() or a templating engine with auto-escaping. Add Content-Security-Policy: script-src 'self' to limit script execution.",
          cvss_score: 7.4,
          cwe_id: "CWE-79",
          scanner_name: "OWASP ZAP",
          scanner_family: "web",
          confidence: 0.92,
        });
        emit({ type: "log", message: `  [XSS CONFIRMED] ${endpoint} param=${paramName} offset=${offset}` });
        break; // One confirmed finding per param is enough
      }
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No reflected XSS confirmed in tested endpoints" });
  }

  emit({
    type: "engine_done",
    engine: "OWASP ZAP/XSS",
    message: `XSS check complete — ${findings.length} confirmed issue(s)`,
  });

  return findings;
}

function buildUrl(endpoint: string, param: string, value: string): string {
  return `${endpoint}${endpoint.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(value)}`;
}
