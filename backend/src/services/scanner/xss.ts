import { ScanContext, ScanFinding, ctxFetch, isInScope, isWafBlock, handleWafBlock } from "./types";
import { runOpenApiDiscovery } from "./openapi";
import { createOastClient } from "./oast";

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
  const { targetUrl, emit, discoveredEndpoints, discoveredForms, discoveredParams, profile } = ctx;

  // Populate OpenAPI-derived params if not already done
  if (discoveredParams.length === 0) await runOpenApiDiscovery(ctx);
  const findings: ScanFinding[] = [];
  const seen = new Set<string>();

  emit({ type: "engine_start", engine: "Bug-Finder/XSS", message: "Probing for reflected XSS vectors" });

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
        if (isWafBlock(res, body)) { handleWafBlock(ctx, endpoint); break; }
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
        const lineNumber = body.slice(0, offset).split("\n").length;
        const snippet = body.slice(Math.max(0, offset - 120), offset + 120);

        // ── Fix 6: Playwright DOM XSS check ───────────────────────────────
        let domXssConfirmed = false;
        const playwrightUrl = process.env["PLAYWRIGHT_URL"];
        if (playwrightUrl) {
          try {
            const pwRes = await fetch(`${playwrightUrl}/check-xss`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ url: testUrl, marker: probe.marker }),
              signal: AbortSignal.timeout(10000),
            });
            if (pwRes.ok) {
              const pwData = await pwRes.json().catch(() => null) as { executed?: boolean } | null;
              domXssConfirmed = pwData?.executed === true;
            }
          } catch { /* Playwright service unavailable — skip DOM check */ }
        }

        findings.push({
          title: domXssConfirmed ? `DOM XSS Confirmed in Parameter: ${paramName}` : `Reflected XSS in Parameter: ${paramName}`,
          category: "XSS",
          severity: domXssConfirmed ? "critical" : "high",
          endpoint,
          description: domXssConfirmed
            ? `Parameter "${paramName}" is confirmed DOM-executed XSS. The payload was reflected in the HTML response AND executed by the browser's JavaScript engine, confirming real-world exploitability.`
            : `Parameter "${paramName}" reflects unsanitized user input directly into the HTML response. Confirmed with two independent probes. An attacker can craft a malicious URL that executes arbitrary JavaScript in the victim's browser when clicked.`,
          evidence: [
            `GET ${testUrl}`,
            `Payload: ${probe.payload}`,
            `Marker reflected unencoded at HTML line ${lineNumber} (byte offset ${offset})`,
            `\nContext:\n${snippet}`,
            `\nConfirmation: GET ${confirmUrl}`,
            `Confirmation marker "${confirmProbe.marker}" also reflected`,
            domXssConfirmed ? `\nPlaywright DOM check: marker executed in browser context — DOM XSS confirmed` : "",
          ].filter(Boolean).join("\n"),
          recommended_fix: "HTML-encode all user input before rendering: use escapeHtml() or a templating engine with auto-escaping. Add Content-Security-Policy: script-src 'self' to limit script execution.",
          cvss_score: domXssConfirmed ? 8.8 : 7.4,
          cwe_id: "CWE-79",
          scanner_name: "Bug-Finder/XSS",
          scanner_family: "web",
          confidence: domXssConfirmed ? 0.98 : 0.92,
        });
        emit({ type: "log", message: `  [XSS${domXssConfirmed ? " DOM-CONFIRMED" : " CONFIRMED"}] ${endpoint} param=${paramName} line=${lineNumber}` });
        break; // One confirmed finding per param is enough
      }
    }
  }

  // ── POST/JSON body XSS injection ──────────────────────────────────────────
  // Reflected XSS via JSON body — covers APIs that echo back field values in HTML/JSON responses
  if (profile !== "quick") {
    const jsonEndpoints = endpoints.slice(0, Math.min(4, budget));
    for (const endpoint of jsonEndpoints) {
      for (const paramName of PARAM_NAMES.slice(0, 4)) {
        const probe = XSS_PROBES[0]!;
        const jsonKey = `${endpoint}:${paramName}:json`;
        if (seen.has(jsonKey)) continue;

        const res = await ctxFetch(ctx, endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "application/json, text/html, */*" },
          body: JSON.stringify({ [paramName]: probe.payload }),
        });
        if (!res) continue;

        const ct = res.headers.get("content-type") ?? "";
        if (!ct.includes("html") && !ct.includes("text") && !ct.includes("json")) continue;

        const body = await res.text().catch(() => "");
        if (!body.includes(probe.marker)) continue;

        const encodedMarker = probe.marker.replace(/</g, "&lt;").replace(/>/g, "&gt;");
        if (body.includes(encodedMarker) && !body.includes(`<${probe.marker.replace(/[<>]/g, "")}`)) continue;

        // Confirm with second marker
        const confirmProbe = XSS_CONFIRM_PROBES[0]!;
        const confirmRes = await ctxFetch(ctx, endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "application/json, text/html, */*" },
          body: JSON.stringify({ [paramName]: confirmProbe.payload }),
        });
        const confirmBody = confirmRes ? await confirmRes.text().catch(() => "") : "";
        if (!confirmBody.includes(confirmProbe.marker)) continue;

        seen.add(jsonKey);
        const offset = body.indexOf(probe.marker);
        const lineNumber = body.slice(0, offset).split("\n").length;
        const snippet = body.slice(Math.max(0, offset - 100), offset + 100);

        findings.push({
          title: `Reflected XSS in JSON Body Parameter: ${paramName}`,
          category: "XSS",
          severity: "high",
          endpoint,
          description: `JSON body field "${paramName}" reflects unsanitized input into the response. Confirmed with two independent markers. APIs that echo JSON fields in HTML or JS responses are vulnerable to XSS even without URL parameters.`,
          evidence: [
            `POST ${endpoint}`,
            `Content-Type: application/json`,
            `Body: ${JSON.stringify({ [paramName]: probe.payload })}`,
            `Marker reflected unencoded at response line ${lineNumber} (byte offset ${offset})`,
            `\nContext:\n${snippet}`,
            `\nConfirmation: ${JSON.stringify({ [paramName]: confirmProbe.payload })} → marker "${confirmProbe.marker}" also reflected`,
          ].join("\n"),
          recommended_fix: "HTML-encode all values before inserting them into HTML — even values sourced from JSON bodies. Use auto-escaping templates and set Content-Security-Policy.",
          cvss_score: 7.4,
          cwe_id: "CWE-79",
          scanner_name: "Bug-Finder/XSS",
          scanner_family: "web",
          confidence: 0.91,
        });
        emit({ type: "log", message: `  [XSS JSON-BODY] ${endpoint} field=${paramName} line=${lineNumber}` });
      }
    }
  }

  // ── Stored XSS tracking ───────────────────────────────────────────────────
  // Inject into POST (write) endpoints, then probe GET (read) endpoints for reflection
  if (profile === "deep") {
    const writeEndpoints = endpoints.filter(ep => ep.includes("/api"));
    const readEndpoints = endpoints.filter(ep => !ep.includes("/api") || ep.includes("/api/feed") || ep.includes("/api/comments"));
    const storedMarker = `xssstored${Date.now().toString(36)}`;

    for (const writeEp of writeEndpoints.slice(0, 3)) {
      // Submit stored XSS payload
      await ctxFetch(ctx, writeEp, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: `<${storedMarker}>`, message: `<${storedMarker}>`, content: `<${storedMarker}>`, comment: `<${storedMarker}>` }),
      });
    }

    // Wait briefly for server to process
    await new Promise(r => setTimeout(r, 1500));

    // Check read endpoints for reflection of stored marker
    for (const readEp of readEndpoints.slice(0, 5)) {
      const res = await ctxFetch(ctx, readEp);
      if (!res) continue;
      const body = await res.text().catch(() => "");
      if (!body.includes(storedMarker)) continue;

      const encodedMarker = storedMarker.replace(/</g, "&lt;").replace(/>/g, "&gt;");
      if (body.includes(encodedMarker)) continue; // encoded = safe

      const offset = body.indexOf(storedMarker);
      const lineNumber = body.slice(0, offset).split("\n").length;
      const storedKey = `stored:${readEp}`;
      if (seen.has(storedKey)) continue;
      seen.add(storedKey);

      findings.push({
        title: "Stored XSS Confirmed",
        category: "XSS",
        severity: "critical",
        endpoint: readEp,
        description: `A stored XSS payload injected into POST write endpoints was reflected unencoded in ${readEp}. Any user who visits this page will execute the attacker's script. This is more severe than reflected XSS as it requires no user interaction beyond visiting the page.`,
        evidence: [
          `Payload injected into write endpoints: <${storedMarker}>`,
          `Marker reflected at GET ${readEp}`,
          `Line ${lineNumber} in response`,
          `Snippet: ${body.slice(Math.max(0, offset - 80), offset + 80)}`,
        ].join("\n"),
        recommended_fix: "HTML-encode all stored content before rendering. Implement a strict Content-Security-Policy. Sanitize all user input at the point of storage.",
        cvss_score: 9.0,
        cwe_id: "CWE-79",
        scanner_name: "Bug-Finder/XSS",
        scanner_family: "web",
        confidence: 0.90,
      });
      emit({ type: "log", message: `  [STORED XSS CONFIRMED] payload stored then reflected at ${readEp} line=${lineNumber}` });
    }
  }

  // ── Blind XSS via OOB (stored XSS in delayed/admin contexts) ───────────────
  // Reflected XSS detection only catches immediate reflection. Stored XSS that
  // fires in admin panels, email templates, or PDF renderers needs out-of-band
  // confirmation. We inject a payload that calls home to the interactsh server
  // and poll for the callback — if it fires, stored XSS is confirmed.
  if (profile !== "quick") {
    const oast = await createOastClient();
    if (oast) {
      emit({ type: "log", message: "OOB blind XSS probe enabled (interactsh connected)" });
      const writeEndpoints = discoveredEndpoints.filter(ep => ep.includes("/api") && isInScope(ctx, ep)).slice(0, 5);

      for (const ep of writeEndpoints) {
        const tag = `xss-${ep.replace(/[^a-z0-9]/gi, "").slice(-12).toLowerCase()}`;
        const oobUrl = oast.allocate(tag);
        // Payload: script tag that calls the OOB URL — fires when any user/admin views the stored content
        const oobPayload = `<script src="${oobUrl}"></script>`;
        const imgPayload = `<img src="${oobUrl}" onerror="fetch('${oobUrl}')">`;

        // Inject into common write fields
        await ctxFetch(ctx, ep, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: oobPayload, message: oobPayload, content: oobPayload,
            comment: imgPayload, title: oobPayload, description: oobPayload,
            body: oobPayload,
          }),
        });

        // Also inject via form fields if available
        for (const form of discoveredForms.filter(f => f.method === "POST").slice(0, 2)) {
          const formBody = new URLSearchParams();
          for (const field of form.fields) formBody.set(field, oobPayload);
          await ctxFetch(ctx, form.action, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: formBody.toString(),
          });
        }

        // Poll interactsh — give server 8 seconds for async rendering (email/PDF/admin panel)
        const fired = await oast.poll(tag, 8000);
        if (fired) {
          const blindKey = `blind-xss:${ep}`;
          if (!seen.has(blindKey)) {
            seen.add(blindKey);
            findings.push({
              title: "Blind Stored XSS — Out-of-Band Callback Confirmed",
              category: "XSS",
              severity: "critical",
              endpoint: ep,
              description: `A blind stored XSS payload was injected into ${ep} and triggered an out-of-band HTTP callback to ${oobUrl}. This confirms the payload was stored server-side and executed in a context invisible to the scanner (admin panel, email template, PDF renderer, or webhook). Any administrator or recipient who views the content will execute the attacker's script.`,
              evidence: [
                `POST ${ep}`,
                `Injected payload: ${oobPayload}`,
                `OOB callback URL: ${oobUrl}`,
                `Interactsh callback received: YES (polled after 8s)`,
                ``,
                `This is a blind stored XSS — the script executed in a delayed or privileged context.`,
                `Severity is critical because it likely fires for privileged users (admins, staff).`,
              ].join("\n"),
              recommended_fix: "HTML-encode all stored user content before rendering. Implement a strict Content-Security-Policy with script-src 'self'. Sanitize HTML at storage time using DOMPurify or equivalent. Audit all admin/email/PDF rendering pipelines for stored XSS vectors.",
              cvss_score: 9.3,
              cwe_id: "CWE-79",
              scanner_name: "Bug-Finder/XSS",
              scanner_family: "web",
              confidence: 0.97,
            });
            emit({ type: "log", message: `  [BLIND XSS CONFIRMED via OOB] ${ep} → callback at ${oobUrl}` });
          }
        } else {
          emit({ type: "log", message: `  OOB blind XSS probe at ${ep} — no callback (not stored or not rendered yet)` });
        }
      }
    } else {
      emit({ type: "log", message: "OOB blind XSS skipped — INTERACTSH_URL not configured" });
    }
  }

  // ── Form-based XSS injection ────────────────────────────────────────────────
  if (discoveredForms.length > 0) {
    emit({ type: "log", message: `Testing ${discoveredForms.length} discovered form(s) for XSS...` });
    for (const form of discoveredForms.slice(0, profile === "quick" ? 2 : 5)) {
      const probe = XSS_PROBES[0]!;
      const confirmProbe = XSS_CONFIRM_PROBES[0]!;
      for (const field of form.fields.slice(0, 4)) {
        const formKey = `form:${form.action}:${field}`;
        if (seen.has(formKey)) continue;

        const submitForm = async (payload: string) => {
          const body = new URLSearchParams();
          for (const f of form.fields) body.set(f, f === field ? payload : "test");
          return ctxFetch(ctx, form.action, {
            method: form.method,
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: body.toString(),
          });
        };

        const res = await submitForm(probe.payload);
        if (!res) continue;
        const ct = res.headers.get("content-type") ?? "";
        if (!ct.includes("html") && !ct.includes("text") && !ct.includes("json")) continue;
        const respBody = await res.text().catch(() => "");
        if (!respBody.includes(probe.marker)) continue;
        const encodedMarker = probe.marker.replace(/</g, "&lt;").replace(/>/g, "&gt;");
        if (respBody.includes(encodedMarker) && !respBody.includes(`<${probe.marker.replace(/[<>]/g, "")}`)) continue;

        const confirmRes = await submitForm(confirmProbe.payload);
        const confirmBody = confirmRes ? await confirmRes.text().catch(() => "") : "";
        if (!confirmBody.includes(confirmProbe.marker)) continue;

        seen.add(formKey);
        const offset = respBody.indexOf(probe.marker);
        findings.push({
          title: `Reflected XSS in Form Field: ${field}`,
          category: "XSS",
          severity: "high",
          endpoint: form.action,
          description: `Form field "${field}" at ${form.action} reflects unsanitized input into the response. Confirmed with two independent markers via form submission (${form.method} application/x-www-form-urlencoded).`,
          evidence: [
            `${form.method} ${form.action}`,
            `Content-Type: application/x-www-form-urlencoded`,
            `Field: ${field}=${probe.payload}`,
            `Marker reflected unencoded at byte offset ${offset}`,
            `Context: ${respBody.slice(Math.max(0, offset - 100), offset + 100)}`,
            `Confirmation: "${confirmProbe.marker}" also reflected`,
          ].join("\n"),
          recommended_fix: "HTML-encode all form field values before rendering. Use auto-escaping templates.",
          cvss_score: 7.4,
          cwe_id: "CWE-79",
          scanner_name: "Bug-Finder/XSS",
          scanner_family: "web",
          confidence: 0.92,
        });
        emit({ type: "log", message: `  [XSS FORM] ${form.action} field=${field}` });
      }
    }
  }

  // ── OpenAPI param-driven XSS ────────────────────────────────────────────────
  if (discoveredParams.length > 0 && profile !== "quick") {
    const queryParams = discoveredParams.filter(p => p.location === "query").slice(0, 10);
    emit({ type: "log", message: `Testing ${queryParams.length} OpenAPI-discovered query params for XSS...` });
    for (const dp of queryParams) {
      const [method, url] = dp.endpoint.split(" ") as [string, string];
      if (method !== "GET" && method !== "POST") continue;
      const probe = XSS_PROBES[0]!;
      const testUrl = `${url}${url.includes("?") ? "&" : "?"}${dp.name}=${encodeURIComponent(probe.payload)}`;
      const paramKey = `openapi:${url}:${dp.name}`;
      if (seen.has(paramKey)) continue;
      const res = await ctxFetch(ctx, testUrl);
      if (!res) continue;
      const body = await res.text().catch(() => "");
      if (!body.includes(probe.marker)) continue;
      const encodedMarker = probe.marker.replace(/</g, "&lt;").replace(/>/g, "&gt;");
      if (body.includes(encodedMarker)) continue;
      const confirmProbe = XSS_CONFIRM_PROBES[0]!;
      const confirmUrl = `${url}${url.includes("?") ? "&" : "?"}${dp.name}=${encodeURIComponent(confirmProbe.payload)}`;
      const confirmRes = await ctxFetch(ctx, confirmUrl);
      const confirmBody = confirmRes ? await confirmRes.text().catch(() => "") : "";
      if (!confirmBody.includes(confirmProbe.marker)) continue;
      seen.add(paramKey);
      const offset = body.indexOf(probe.marker);
      findings.push({
        title: `Reflected XSS in OpenAPI Parameter: ${dp.name}`,
        category: "XSS",
        severity: "high",
        endpoint: url,
        description: `Parameter "${dp.name}" (discovered via OpenAPI spec) reflects unsanitized input. Confirmed with two independent markers.`,
        evidence: [`GET ${testUrl}`, `Marker at offset ${offset}`, `Context: ${body.slice(Math.max(0, offset - 100), offset + 100)}`].join("\n"),
        recommended_fix: "HTML-encode all output. Use auto-escaping templates and Content-Security-Policy.",
        cvss_score: 7.4,
        cwe_id: "CWE-79",
        scanner_name: "Bug-Finder/XSS",
        scanner_family: "web",
        confidence: 0.91,
      });
      emit({ type: "log", message: `  [XSS OpenAPI-param] ${url} param=${dp.name}` });
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No reflected XSS confirmed in tested endpoints" });
  }

  emit({
    type: "engine_done",
    engine: "Bug-Finder/XSS",
    message: `XSS check complete — ${findings.length} confirmed issue(s)`,
  });

  return findings;
}

function buildUrl(endpoint: string, param: string, value: string): string {
  return `${endpoint}${endpoint.includes("?") ? "&" : "?"}${param}=${encodeURIComponent(value)}`;
}
