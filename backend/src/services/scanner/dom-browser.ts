import { ScanContext, ScanFinding, safeFetch } from "./types";
import { logger } from "../../lib/logger";

export async function runDomBrowserScan(ctx: ScanContext): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const targetUrl = ctx.targetUrl;

  ctx.emit({ type: "engine_start", engine: "DOM Browser", message: "Running DOM-based security checks..." });

  const mainRes = await safeFetch(targetUrl, {}, 10000);
  if (!mainRes) {
    ctx.emit({ type: "engine_done", engine: "DOM Browser", message: "Target unreachable" });
    return findings;
  }

  const html = await mainRes.text().catch(() => "");
  if (!html || html.length < 50) {
    ctx.emit({ type: "engine_done", engine: "DOM Browser", message: "No HTML content to analyze" });
    return findings;
  }

  // 1. Detect inline event handlers (DOM-based XSS sinks)
  const inlineEventPatterns = [
    { name: "onclick", pattern: /onclick\s*=\s*["'][^"']*["']/gi },
    { name: "onerror", pattern: /onerror\s*=\s*["'][^"']*["']/gi },
    { name: "onload", pattern: /onload\s*=\s*["'][^"']*["']/gi },
    { name: "onmouseover", pattern: /onmouseover\s*=\s*["'][^"']*["']/gi },
  ];

  for (const event of inlineEventPatterns) {
    const matches = html.match(event.pattern);
    if (matches && matches.length > 0) {
      findings.push({
        title: `DOM XSS Sink: Inline ${event.name} Handler`,
        category: "Cross-Site Scripting",
        severity: "medium",
        endpoint: targetUrl,
        description: `Found ${matches.length} inline ${event.name} event handler(s) in the HTML. Inline event handlers are a common DOM-based XSS sink. Example: "${matches[0].slice(0, 80)}"`,
        evidence: matches.slice(0, 3).join("\n"),
        recommended_fix: "Replace inline event handlers with addEventListener() and properly sanitize user input. Use a Content Security Policy that disallows 'unsafe-inline'.",
        cvss_score: 5.4,
        cwe_id: "CWE-79",
        scanner_name: "dom-browser-events",
        scanner_family: "dom",
        confidence: 0.7,
      });
      ctx.emit({ type: "log", message: `  Found ${matches.length} inline ${event.name} handlers` });
    }
  }

  // 2. Detect missing Subresource Integrity (SRI) on external scripts
  const scriptPattern = /<script[^>]*src\s*=\s*["'](https?:[^"']+)["'][^>]*>/gi;
  const scriptMatches = [...html.matchAll(scriptPattern)];
  const scriptsWithoutSRI: string[] = [];

  for (const match of scriptMatches) {
    const fullTag = match[0];
    const src = match[1];
    if (!fullTag.includes("integrity=") && !fullTag.includes("integrity =")) {
      scriptsWithoutSRI.push(src);
    }
  }

  if (scriptsWithoutSRI.length > 0) {
    findings.push({
      title: `Missing Subresource Integrity (SRI) on ${scriptsWithoutSRI.length} External Script(s)`,
      category: "Security Misconfiguration",
      severity: "medium",
      endpoint: targetUrl,
      description: `${scriptsWithoutSRI.length} external script(s) loaded without integrity hashes. If the CDN is compromised, malicious code could be injected. Example: ${scriptsWithoutSRI[0]}`,
      evidence: scriptsWithoutSRI.slice(0, 5).join("\n"),
      recommended_fix: "Add integrity=\"sha384-...\" attributes to all external script tags. Use tools like srihash.org to generate hashes.",
      cvss_score: 5.3,
      cwe_id: "CWE-353",
      scanner_name: "dom-browser-sri",
      scanner_family: "dom",
      confidence: 0.85,
    });
    ctx.emit({ type: "log", message: `  ${scriptsWithoutSRI.length} scripts missing SRI` });
  }

  // 3. Detect CSP in meta tags vs header
  const metaCsp = html.match(/<meta[^>]*http-equiv\s*=\s*["']Content-Security-Policy["'][^>]*content\s*=\s*["']([^"']+)["']/i);
  const headerCsp = mainRes.headers.get("content-security-policy") ?? "";

  if (metaCsp && !headerCsp) {
    ctx.emit({ type: "log", message: "  CSP defined in meta tag only (weaker than HTTP header)" });
  }

  // 4. Detect mixed content (HTTP resources on HTTPS page)
  if (targetUrl.startsWith("https://")) {
    const httpPatterns = [
      { name: "HTTP scripts", pattern: /<script[^>]*src\s*=\s*["']http:\/\//gi },
      { name: "HTTP images", pattern: /<img[^>]*src\s*=\s*["']http:\/\//gi },
      { name: "HTTP stylesheets", pattern: /<link[^>]*href\s*=\s*["']http:\/\//gi },
    ];

    for (const { name, pattern } of httpPatterns) {
      const httpMatches = html.match(pattern);
      if (httpMatches && httpMatches.length > 0) {
        findings.push({
          title: `Mixed Content: ${httpMatches.length} ${name} Loaded Over HTTP`,
          category: "TLS",
          severity: "high",
          endpoint: targetUrl,
          description: `${httpMatches.length} ${name} are loaded over HTTP on an HTTPS page, creating a mixed content vulnerability. Browsers may block or warn about this.`,
          evidence: httpMatches.slice(0, 3).join("\n"),
          recommended_fix: "Change all resource URLs to HTTPS. Use protocol-relative URLs (//) or auto-upgrade via CSP upgrade-insecure-requests.",
          cvss_score: 6.1,
          cwe_id: "CWE-311",
          scanner_name: "dom-browser-mixed",
          scanner_family: "dom",
          confidence: 0.9,
        });
      }
    }
  }

  // 5. Detect client-side JavaScript patterns (eval, innerHTML, document.write)
  const scriptTags = html.match(/<script\b[^>]*>([\s\S]*?)<\/script>/gi) ?? [];
  const dangerousPatterns: Array<{ name: string; pattern: RegExp; severity: string }> = [
    { name: "eval()", pattern: /\beval\s*\(/gi, severity: "high" },
    { name: "innerHTML assignment", pattern: /\.innerHTML\s*=/gi, severity: "medium" },
    { name: "document.write()", pattern: /document\.write\s*\(/gi, severity: "medium" },
  ];

  for (const { name, pattern, severity } of dangerousPatterns) {
    for (const script of scriptTags) {
      const matches = script.match(pattern);
      if (matches && matches.length > 0) {
        const lineIdx = script.indexOf(matches[0]);
        const context = script.slice(Math.max(0, lineIdx - 40), Math.min(script.length, lineIdx + 40));
        findings.push({
          title: `Client-Side XSS Sink: ${name}`,
          category: "Cross-Site Scripting",
          severity: severity as ScanFinding["severity"],
          endpoint: targetUrl,
          description: `Dangerous DOM manipulation function "${name}" found in inline JavaScript. User-controlled data reaching these sinks enables DOM-based XSS. Context: "${context}..."`,
          evidence: `Pattern: ${name}\nContext: ${context}\nFull match: ${matches[0]}`,
          recommended_fix: "Replace with safe alternatives: eval → Function constructor with sanitized input, innerHTML → textContent or DOMPurify, document.write → DOM manipulation APIs.",
          cvss_score: severity === "high" ? 6.1 : 4.7,
          cwe_id: "CWE-79",
          scanner_name: "dom-browser-js",
          scanner_family: "dom",
          confidence: 0.75,
        });
        ctx.emit({ type: "log", message: `  Found ${name} in inline script` });
        break; // one per script
      }
    }
  }

  // 6. Detect localStorage/sessionStorage usage patterns
  const storagePattern = /\b(localStorage|sessionStorage)\.(setItem|getItem)\s*\(/gi;
  for (const script of scriptTags) {
    if (storagePattern.test(script)) {
      findings.push({
        title: "Web Storage Used for Potentially Sensitive Data",
        category: "Security Misconfiguration",
        severity: "info",
        endpoint: targetUrl,
        description: "localStorage/sessionStorage usage detected. Web Storage is accessible by any JavaScript on the same origin and is vulnerable to XSS-based data theft.",
        evidence: "localStorage.getItem or sessionStorage.setItem pattern detected in inline script",
        recommended_fix: "Use HttpOnly cookies for session tokens instead of localStorage. Encrypt sensitive data before storing in web storage.",
        cvss_score: 2.5,
        cwe_id: "CWE-922",
        scanner_name: "dom-browser-storage",
        scanner_family: "dom",
        confidence: 0.8,
      });
      ctx.emit({ type: "log", message: "  localStorage/sessionStorage usage detected" });
      break;
    }
  }

  // 7. Check viewport meta for mobile security
  const hasViewport = html.includes("viewport");
  if (!hasViewport) {
    findings.push({
      title: "Missing Viewport Meta Tag",
      category: "UI/UX",
      severity: "info",
      endpoint: targetUrl,
      description: "The viewport meta tag is missing, which can affect mobile rendering and security.",
      evidence: "No <meta name=\"viewport\"> found in HTML",
      recommended_fix: 'Add <meta name="viewport" content="width=device-width, initial-scale=1"> to <head>.',
      cvss_score: 0,
      cwe_id: "N/A",
      scanner_name: "dom-browser-viewport",
      scanner_family: "dom",
      confidence: 0.95,
    });
  }

  ctx.emit({ type: "engine_done", engine: "DOM Browser", message: `DOM scan complete — ${findings.length} issue(s) found` });
  return findings;
}
