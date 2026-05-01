import { ScanContext, ScanFinding, safeFetch } from "./types";

export async function runSubdomainEnum(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Subfinder/crt.sh", message: "Enumerating subdomains via certificate transparency" });

  let hostname: string;
  try { hostname = new URL(targetUrl).hostname; } catch {
    emit({ type: "engine_done", engine: "Subfinder/crt.sh", message: "Skipped — invalid URL" });
    return findings;
  }

  if (hostname === "localhost" || hostname.startsWith("127.") || hostname.endsWith(".replit.dev")) {
    emit({ type: "log", message: "Skipping subdomain enum for local/dev host" });
    emit({ type: "engine_done", engine: "Subfinder/crt.sh", message: "Skipped (local host)" });
    return findings;
  }

  // Query crt.sh for certificate transparency logs
  const crtUrl = `https://crt.sh/?q=%.${hostname}&output=json`;
  emit({ type: "log", message: `Querying crt.sh for %.${hostname}` });

  const res = await safeFetch(crtUrl, { headers: { "Accept": "application/json" } }, 15000);
  if (!res || res.status !== 200) {
    emit({ type: "log", message: "crt.sh unreachable or returned error" });
    emit({ type: "engine_done", engine: "Subfinder/crt.sh", message: "Subdomain enum skipped (crt.sh unavailable)" });
    return findings;
  }

  let certs: Array<{ name_value: string }> = [];
  try {
    certs = await res.json();
  } catch {
    emit({ type: "log", message: "Could not parse crt.sh response" });
    emit({ type: "engine_done", engine: "Subfinder/crt.sh", message: "Parse error" });
    return findings;
  }

  const subdomains = new Set<string>();
  for (const cert of certs) {
    const names = (cert.name_value ?? "").split("\n");
    for (const name of names) {
      const clean = name.trim().replace(/^\*\./, "");
      if (clean && clean.endsWith(hostname) && clean !== hostname) {
        subdomains.add(clean);
      }
    }
  }

  emit({ type: "log", message: `Found ${subdomains.size} unique subdomains from certificate transparency` });

  if (subdomains.size > 30) {
    findings.push({
      title: `Large Attack Surface: ${subdomains.size} Subdomains Discovered`,
      category: "Attack Surface",
      severity: "medium",
      endpoint: hostname,
      description: `Certificate transparency logs reveal ${subdomains.size} subdomains. Each subdomain is a potential entry point. Large attack surfaces increase the probability of misconfigured or forgotten services.`,
      evidence: `crt.sh query for %.${hostname}\nSubdomains discovered:\n${[...subdomains].slice(0, 20).join("\n")}${subdomains.size > 20 ? `\n... and ${subdomains.size - 20} more` : ""}`,
      recommended_fix: "Audit all subdomains. Decommission unused ones. Apply the same security controls to every subdomain.",
      cvss_score: 5.3,
      cwe_id: "CWE-200",
      scanner_name: "Subfinder",
      scanner_family: "network",
      confidence: 0.95,
    });
  }

  // Check for sensitive subdomains
  const sensitivePatterns = ["dev", "staging", "test", "admin", "internal", "beta", "old", "backup", "jenkins", "ci", "vpn", "mail"];
  for (const sub of subdomains) {
    const prefix = sub.replace(`.${hostname}`, "").toLowerCase();
    if (sensitivePatterns.some(p => prefix.includes(p))) {
      findings.push({
        title: `Sensitive Subdomain Exposed: ${sub}`,
        category: "Attack Surface",
        severity: "medium",
        endpoint: `https://${sub}`,
        description: `The subdomain "${sub}" suggests a development, staging, or internal service. These often have weaker security controls than production.`,
        evidence: `Found in crt.sh certificate transparency logs\nSubdomain: ${sub}`,
        recommended_fix: `Restrict access to ${sub}. Apply IP allowlisting or VPN requirement. Ensure it has the same security posture as production.`,
        cvss_score: 5.3,
        cwe_id: "CWE-200",
        scanner_name: "Subfinder",
        scanner_family: "network",
        confidence: 0.8,
      });
      // Add to discovered endpoints for further scanning
      const subUrl = `https://${sub}`;
      if (!discoveredEndpoints.includes(subUrl)) discoveredEndpoints.push(subUrl);
    }
  }

  emit({ type: "engine_done", engine: "Subfinder/crt.sh", message: `Found ${subdomains.size} subdomains, ${findings.length} issue(s)` });
  return findings;
}

export async function runWaybackCrawl(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, discoveredEndpoints, profile } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Wayback Machine", message: "Querying Wayback Machine for historical endpoints" });

  let hostname: string;
  try { hostname = new URL(targetUrl).hostname; } catch {
    emit({ type: "engine_done", engine: "Wayback Machine", message: "Skipped" });
    return findings;
  }
  if (hostname === "localhost" || hostname.startsWith("127.") || hostname.endsWith(".replit.dev")) {
    emit({ type: "engine_done", engine: "Wayback Machine", message: "Skipped (local host)" });
    return findings;
  }

  const budget = profile === "deep" ? 100 : 30;
  const apiUrl = `https://web.archive.org/cdx/search/cdx?url=${hostname}/*&output=json&limit=${budget}&fl=original&collapse=urlkey&filter=statuscode:200`;

  const res = await safeFetch(apiUrl, {}, 15000);
  if (!res || res.status !== 200) {
    emit({ type: "log", message: "Wayback Machine unavailable" });
    emit({ type: "engine_done", engine: "Wayback Machine", message: "Unavailable" });
    return findings;
  }

  let rows: string[][] = [];
  try { rows = await res.json(); } catch {
    emit({ type: "engine_done", engine: "Wayback Machine", message: "Parse error" });
    return findings;
  }

  const urls = rows.slice(1).map(r => r[0]).filter(Boolean);
  let added = 0;
  for (const url of urls) {
    try {
      const parsed = new URL(url);
      if (!discoveredEndpoints.includes(parsed.toString())) {
        discoveredEndpoints.push(parsed.toString());
        added++;
      }
    } catch { /* skip */ }
  }

  emit({ type: "log", message: `Wayback Machine: ${urls.length} historical URLs found, ${added} added to scan scope` });

  if (urls.length > 0) {
    const oldPaths = urls.filter(u => /\.(bak|old|backup|orig|tmp|sql|dump)/.test(u));
    if (oldPaths.length > 0) {
      findings.push({
        title: `Historical Backup/Archive Files in Wayback Machine`,
        category: "Information Disclosure",
        severity: "medium",
        endpoint: targetUrl,
        description: `The Wayback Machine has archived ${oldPaths.length} URLs with backup/archive file extensions. These files may still be accessible and contain sensitive source code or data.`,
        evidence: `URLs with sensitive extensions:\n${oldPaths.slice(0, 10).join("\n")}`,
        recommended_fix: "Check if these URLs are still accessible. Remove backup files from the web root and verify they cannot be downloaded.",
        cvss_score: 5.3,
        cwe_id: "CWE-538",
        scanner_name: "Wayback Machine",
        scanner_family: "web",
        confidence: 0.75,
      });
    }
  }

  emit({ type: "engine_done", engine: "Wayback Machine", message: `${urls.length} historical URLs processed, ${findings.length} issue(s)` });
  return findings;
}
