import { ScanContext, ScanFinding, ctxFetch } from "./types";

const UPLOAD_PATHS = ["/upload", "/api/upload", "/file/upload", "/files", "/media/upload", "/images/upload", "/uploads", "/api/files"];
const DANGEROUS_EXTENSIONS = [".php", ".php5", ".phtml", ".asp", ".aspx", ".jsp", ".jspx", ".shtml", ".cfm"];
const POLYGLOT_PAYLOADS = [
  { filename: "test.php.jpg", content: "GIF89a\n<?php echo 'rce'; ?>\nGIF", contentType: "image/gif" },
  { filename: "test.svg", content: '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', contentType: "image/svg+xml" },
  { filename: "../../../test.txt", content: "path traversal test", contentType: "text/plain" },
];

function buildMultipartBody(filename: string, content: string, fieldName: string = "file"): { body: Buffer; boundary: string } {
  const boundary = "----WebKitFormBoundary" + Math.random().toString(36).slice(2);
  const CRLF = "\r\n";
  const body = Buffer.concat([
    Buffer.from(`--${boundary}${CRLF}`),
    Buffer.from(`Content-Disposition: form-data; name="${fieldName}"; filename="${filename}"${CRLF}`),
    Buffer.from(`Content-Type: application/octet-stream${CRLF}${CRLF}`),
    Buffer.from(content),
    Buffer.from(`${CRLF}--${boundary}--${CRLF}`),
  ]);
  return { body, boundary };
}

export async function runFileUploadCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints, profile } = ctx;
  const findings: ScanFinding[] = [];
  const seen = new Set<string>();

  emit({ type: "engine_start", engine: "Bug-Finder/Upload", message: "Probing file upload endpoints for abuse vectors" });

  const base = new URL(targetUrl);

  // Check known upload paths
  for (const path of UPLOAD_PATHS) {
    const url = `${base.origin}${path}`;
    const headRes = await ctxFetch(ctx, url, { method: "OPTIONS" });
    if (!headRes || headRes.status === 404) continue;

    emit({ type: "log", message: `  File upload endpoint found: ${path}` });

    for (const probe of POLYGLOT_PAYLOADS.slice(0, profile === "quick" ? 1 : 2)) {
      const { body, boundary } = buildMultipartBody(probe.filename, probe.content);
      const uploadRes = await ctxFetch(ctx, url, {
        method: "POST",
        headers: { "Content-Type": `multipart/form-data; boundary=${boundary.slice(2)}` },
        body,
      });

      if (!uploadRes) continue;
      const respBody = await uploadRes.text().catch(() => "");
      const key = `${url}:${probe.filename}`;
      if (seen.has(key)) continue;
      seen.add(key);

      if (uploadRes.status === 200 || uploadRes.status === 201) {
        if (probe.filename.includes(".php")) {
          // ── Execution verification: probe the URL where the file was stored ──
          // Accepting an upload is NOT sufficient to confirm RCE — the file must
          // also be accessible and executed by the server. Extract the stored URL
          // from the response body (common patterns: "url", "path", "location"),
          // then probe it with a GET and check for the output of `echo 'rce'`.
          let executedUrl: string | null = null;
          let executionConfirmed = false;

          const urlPatterns = [
            /"url"\s*:\s*"([^"]+)"/i,
            /"path"\s*:\s*"([^"]+)"/i,
            /"file"\s*:\s*"([^"]+)"/i,
            /"location"\s*:\s*"([^"]+)"/i,
            /"src"\s*:\s*"([^"]+)"/i,
          ];
          for (const pat of urlPatterns) {
            const m = respBody.match(pat);
            if (m?.[1]) {
              try {
                executedUrl = new URL(m[1], url).toString();
                break;
              } catch { /* skip */ }
            }
          }
          // Also check Location header
          if (!executedUrl) {
            const loc = uploadRes.headers.get("location");
            if (loc) {
              try { executedUrl = new URL(loc, url).toString(); } catch { /* skip */ }
            }
          }

          if (executedUrl) {
            const execRes = await ctxFetch(ctx, executedUrl);
            if (execRes) {
              const execBody = await execRes.text().catch(() => "");
              // Our uploaded content was: GIF89a\n<?php echo 'rce'; ?>\nGIF
              // If the server executes it, the output will contain 'rce' without the PHP tags
              executionConfirmed = execBody.includes("rce") && !execBody.includes("<?php");
              emit({ type: "log", message: `  Upload exec probe: GET ${executedUrl} → HTTP ${execRes.status}, executed=${executionConfirmed}` });
            }
          }

          const severity = executionConfirmed ? "critical" : "high";
          const confidence = executionConfirmed ? 0.97 : 0.65;
          findings.push({
            title: executionConfirmed
              ? "File Upload RCE Confirmed — PHP Execution Verified"
              : "File Upload: PHP Extension Accepted (Execution Unverified)",
            category: "File Upload",
            severity,
            endpoint: url,
            description: executionConfirmed
              ? `A PHP file disguised as a GIF image was uploaded and then executed by the server. The PHP code ran and returned output, confirming Remote Code Execution. An attacker can upload a web shell to take full control of the server.`
              : `The upload endpoint accepted a file with a PHP extension disguised as an image (${probe.filename}). Execution could not be verified because the file URL was not returned in the response. Manual verification required: if uploaded files are served from the web root without extension restrictions, RCE is possible.`,
            evidence: [
              `POST ${url}`,
              `Filename: ${probe.filename}`,
              `Content-Type: ${probe.contentType}`,
              `File content: ${probe.content.slice(0, 60)}`,
              `HTTP ${uploadRes.status}`,
              `Upload response: ${respBody.slice(0, 200)}`,
              executedUrl ? `\nExecution probe: GET ${executedUrl}` : "\nExecution probe: URL not found in response — unverified",
              executionConfirmed ? "PHP output detected — EXECUTION CONFIRMED" : "",
            ].filter(Boolean).join("\n"),
            recommended_fix: "Validate file type by magic bytes, not extension or MIME type. Store uploads outside the web root or in a CDN with script execution disabled. Use an explicit allowlist of permitted file types. Rename uploaded files server-side.",
            cvss_score: executionConfirmed ? 9.8 : 7.5,
            cwe_id: "CWE-434",
            scanner_name: "Bug-Finder/Upload",
            scanner_family: "web",
            confidence,
          });
          emit({ type: "log", message: `  [UPLOAD ${executionConfirmed ? "RCE CONFIRMED" : "UNVERIFIED"}] ${probe.filename} at ${path}` });
        } else if (probe.filename.includes(".svg")) {
          findings.push({
            title: "File Upload: SVG XSS / Content-Type Confusion",
            category: "File Upload",
            severity: "high",
            endpoint: url,
            description: "The upload endpoint accepts SVG files which can contain embedded JavaScript, leading to stored XSS when the file is rendered in a browser.",
            evidence: `POST ${url}\nFilename: ${probe.filename}\nSVG with embedded script tag accepted\nHTTP ${uploadRes.status}`,
            recommended_fix: "Sanitize SVG files on upload (strip script tags, event handlers). Set Content-Disposition: attachment for uploaded file downloads. Use a dedicated content delivery domain.",
            cvss_score: 7.4,
            cwe_id: "CWE-79",
            scanner_name: "Bug-Finder/Upload",
            scanner_family: "web",
            confidence: 0.82,
          });
        } else if (probe.filename.includes("..")) {
          findings.push({
            title: "File Upload: Path Traversal in Filename",
            category: "File Upload",
            severity: "high",
            endpoint: url,
            description: "The upload endpoint accepted a filename containing path traversal sequences (../). An attacker could overwrite arbitrary files on the server.",
            evidence: `POST ${url}\nFilename: ${probe.filename}\nHTTP ${uploadRes.status}`,
            recommended_fix: "Sanitize filenames on server: use basename() or equivalent to strip directory traversal sequences. Generate server-side filenames rather than using client-provided names.",
            cvss_score: 8.1,
            cwe_id: "CWE-22",
            scanner_name: "Bug-Finder/Upload",
            scanner_family: "web",
            confidence: 0.78,
          });
        }
      }
    }
  }

  if (findings.length === 0) emit({ type: "log", message: "No file upload vulnerabilities detected (or no upload endpoints found)" });
  emit({ type: "engine_done", engine: "Bug-Finder/Upload", message: `File upload check complete — ${findings.length} issue(s)` });
  return findings;
}

export async function runDependencyConfusionCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Bug-Finder/DepConfusion", message: "Checking for dependency confusion attack vectors" });

  // Check for exposed package.json or requirements.txt
  const base = new URL(targetUrl);
  const exposedFiles = [
    { path: "/package.json", type: "npm" },
    { path: "/package-lock.json", type: "npm" },
    { path: "/yarn.lock", type: "npm" },
    { path: "/requirements.txt", type: "python" },
    { path: "/Gemfile", type: "ruby" },
    { path: "/composer.json", type: "php" },
    { path: "/.npmrc", type: "npm config" },
    { path: "/pom.xml", type: "maven" },
  ];

  for (const file of exposedFiles) {
    const url = `${base.origin}${file.path}`;
    const res = await ctxFetch(ctx, url);
    if (!res || res.status !== 200) continue;

    const body = await res.text().catch(() => "");
    if (!body || body.length < 10) continue;

    emit({ type: "log", message: `  [DEP] Found exposed ${file.path}` });

    if (file.type === "npm" && file.path === "/package.json") {
      try {
        const pkg = JSON.parse(body);
        const deps = { ...pkg.dependencies, ...pkg.devDependencies };

        // Check for internal/private package names that could be hijacked
        const internalNames = Object.keys(deps).filter(name =>
          name.startsWith("@internal/") ||
          name.startsWith("@private/") ||
          name.startsWith("@corp/") ||
          (!name.startsWith("@") && !name.includes("/") && name.includes("-internal"))
        );

        if (internalNames.length > 0) {
          findings.push({
            title: "Dependency Confusion: Private Package Names in Public package.json",
            category: "Supply Chain",
            severity: "high",
            endpoint: url,
            description: `The package.json is publicly accessible and contains private/internal package names: ${internalNames.join(", ")}. An attacker can publish a malicious package with the same name to the public npm registry. If the package manager resolves to the public registry first, the malicious code will be installed.`,
            evidence: `GET ${url} → HTTP 200\nInternal packages: ${internalNames.join(", ")}\nFull package.json visible`,
            recommended_fix: "Block public access to package.json files. Use npm's @scope configuration to pin internal packages to a private registry. Consider using npm config to always use private registry for internal scopes.",
            cvss_score: 8.1,
            cwe_id: "CWE-829",
            scanner_name: "Bug-Finder/DepConfusion",
            scanner_family: "web",
            confidence: 0.85,
          });
        }

        findings.push({
          title: `Dependency Manifest Publicly Exposed: ${file.path}`,
          category: "Information Disclosure",
          severity: "medium",
          endpoint: url,
          description: `${file.path} is publicly accessible, exposing the full list of ${Object.keys(deps).length} dependencies. Attackers can fingerprint the tech stack and identify dependencies with known vulnerabilities.`,
          evidence: `GET ${url} → HTTP 200\n${body.slice(0, 300)}`,
          recommended_fix: "Block public access to dependency manifests via web server configuration. These files should not be in the web root.",
          cvss_score: 5.3,
          cwe_id: "CWE-200",
          scanner_name: "Bug-Finder/DepConfusion",
          scanner_family: "web",
          confidence: 0.95,
        });
      } catch { /* JSON parse error */ }
    } else {
      findings.push({
        title: `Sensitive File Exposed: ${file.path}`,
        category: "Information Disclosure",
        severity: "medium",
        endpoint: url,
        description: `The ${file.type} dependency file (${file.path}) is publicly accessible, exposing technology stack details.`,
        evidence: `GET ${url} → HTTP 200\n${body.slice(0, 200)}`,
        recommended_fix: `Configure the web server to deny access to ${file.path}. Move it outside the web root.`,
        cvss_score: 5.3,
        cwe_id: "CWE-200",
        scanner_name: "Bug-Finder/DepConfusion",
        scanner_family: "web",
        confidence: 0.95,
      });
    }
  }

  if (findings.length === 0) emit({ type: "log", message: "No exposed dependency manifests found" });
  emit({ type: "engine_done", engine: "Bug-Finder/DepConfusion", message: `Dependency confusion check complete — ${findings.length} issue(s)` });
  return findings;
}
