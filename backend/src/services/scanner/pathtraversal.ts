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
          const key = `${endpoint}:${param}:traversal`;
          if (!seen.has(key)) {
            seen.add(key);
            const isWin = !!winHit;
            const leakedFile = isWin ? "windows\\win.ini" : "/etc/passwd";
            findings.push({
              title: `Path Traversal — ${isWin ? "win.ini" : "/etc/passwd"} Disclosure`,
              category: "Path Traversal",
              severity: "critical",
              endpoint,
              description: `Parameter "${param}" is vulnerable to path traversal. The server returned contents of ${leakedFile} when the payload "${probe}" was injected. An attacker can read any file the web process has permission to access, including application config, private keys, and credentials.`,
              evidence: [
                `GET ${testUrl}`,
                `Parameter: ${param}`,
                `Payload: ${probe}`,
                `HTTP ${res.status}`,
                ``,
                `File content leaked (${leakedFile}):`,
                body.slice(0, 600),
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
            emit({ type: "log", message: `  [PATH TRAVERSAL] ${leakedFile} leaked at ${endpoint} param=${param}` });
          }
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
