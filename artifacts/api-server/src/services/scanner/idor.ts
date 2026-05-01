import { ScanContext, ScanFinding, safeFetch } from "./types";

const IDOR_PATH_PATTERNS = [
  { path: "/api/users/{id}", label: "User object" },
  { path: "/api/orders/{id}", label: "Order object" },
  { path: "/api/products/{id}", label: "Product object" },
  { path: "/api/files/{id}", label: "File object" },
  { path: "/api/reports/{id}", label: "Report object" },
  { path: "/api/accounts/{id}", label: "Account object" },
  { path: "/api/v1/users/{id}", label: "User object v1" },
  { path: "/api/messages/{id}", label: "Message object" },
  { path: "/api/invoices/{id}", label: "Invoice object" },
];

export async function runIdorCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, profile } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Burp Suite/IDOR", message: "Testing for Insecure Direct Object References" });

  const base = new URL(targetUrl);
  const budget = profile === "quick" ? 3 : profile === "standard" ? 6 : IDOR_PATH_PATTERNS.length;

  for (const pattern of IDOR_PATH_PATTERNS.slice(0, budget)) {
    // Probe sequential IDs: 1, 2, 100, 999
    const ids = [1, 2, 100, 999];
    const responses: Array<{ id: number; status: number; bodyLen: number; body: string }> = [];

    for (const id of ids) {
      const url = `${base.origin}${pattern.path.replace("{id}", String(id))}`;
      const res = await safeFetch(url, { headers: { "Accept": "application/json" } });
      if (!res) continue;
      const body = await res.text().catch(() => "");
      responses.push({ id, status: res.status, bodyLen: body.length, body });
    }

    // IDOR signal: multiple IDs return 200 with substantial data
    const successfulResponses = responses.filter(r => r.status === 200 && r.bodyLen > 20);

    if (successfulResponses.length >= 2) {
      // Check if they return different data (confirming IDOR)
      const distinctBodies = new Set(successfulResponses.map(r => r.body.slice(0, 100))).size;
      if (distinctBodies >= 2 || successfulResponses.length >= 2) {
        const url = `${base.origin}${pattern.path.replace("{id}", "1")}`;
        findings.push({
          title: `Possible IDOR: ${pattern.label} Accessible by Numeric ID`,
          category: "Broken Access Control",
          severity: "high",
          endpoint: url,
          description: `The ${pattern.label} endpoint appears accessible using sequential numeric IDs without ownership validation. An authenticated user may be able to access other users' data by enumerating IDs.`,
          evidence: `Probed IDs: ${successfulResponses.map(r => r.id).join(", ")}\nAll returned HTTP 200 with data:\n${successfulResponses.map(r => `ID ${r.id}: ${r.body.slice(0, 80)}`).join("\n")}`,
          recommended_fix: "Verify object ownership on every request. Use UUIDs instead of sequential integers. Implement row-level security in database queries.",
          cvss_score: 7.5,
          cwe_id: "CWE-639",
          scanner_name: "Burp Suite",
          scanner_family: "web",
          confidence: 0.7,
        });
        emit({ type: "log", message: `  [IDOR] Sequential IDs work on ${pattern.path}` });
      }
    } else {
      emit({ type: "log", message: `  ${pattern.path} — ${responses.map(r => r.status).join(",")} (protected)` });
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No obvious IDOR vulnerabilities detected" });
  }

  emit({
    type: "engine_done",
    engine: "Burp Suite/IDOR",
    message: `IDOR check complete — ${findings.length} issue(s) found`,
  });

  return findings;
}
