import { ScanContext, ScanFinding } from "./types";
import { logger } from "../../lib/logger";

const SHODAN_KEY = process.env["SHODAN_API_KEY"] ?? "";

function getDomain(targetUrl: string): string {
  try { return new URL(targetUrl).hostname; } catch { return targetUrl; }
}

async function queryShodan(domain: string): Promise<Record<string, unknown> | null> {
  if (!SHODAN_KEY) return null;
  try {
    const res = await fetch(`https://api.shodan.io/dns/domain/${domain}?key=${SHODAN_KEY}`, {
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return null;
    return await res.json() as Record<string, unknown>;
  } catch { return null; }
}

async function queryCrtSh(domain: string): Promise<Array<{ name_value: string }> | null> {
  try {
    const res = await fetch(`https://crt.sh/?q=%.${domain}&output=json`, {
      signal: AbortSignal.timeout(8000),
      headers: { "User-Agent": "BugFinderPro/1.0" },
    });
    if (!res.ok) return null;
    return await res.json() as Array<{ name_value: string }>;
  } catch { return null; }
}

export async function runOsintEnrichment(ctx: ScanContext): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const domain = getDomain(ctx.targetUrl);

  try {
    logger.info({ domain }, "Running OSINT enrichment");

    // 1. CRT.sh — Certificate transparency subdomains
    const crtData = await queryCrtSh(domain);
    if (crtData && crtData.length > 0) {
      const subdomains = new Set<string>();
      for (const entry of crtData) {
        if (entry.name_value) {
          for (const name of entry.name_value.split("\n")) {
            const cleaned = name.trim().replace(/^\*\./, "");
            if (cleaned.endsWith(domain) && cleaned !== domain) {
              subdomains.add(cleaned);
            }
          }
        }
      }

      if (subdomains.size > 0) {
        const discovered = [...subdomains].slice(0, 20);
        findings.push({
          title: `Certificate Transparency — ${discovered.length} Subdomains Discovered`,
          severity: "info",
          category: "Attack Surface",
          endpoint: domain,
          cwe_id: "N/A",
          description: `Certificate Transparency logs reveal ${discovered.length} subdomains: ${discovered.slice(0, 10).join(", ")}${discovered.length > 10 ? ` and ${discovered.length - 10} more` : ""}. These may include forgotten staging/dev servers with weaker security.`,
          evidence: `CT Logs at crt.sh for *.${domain}`,
          recommended_fix: "Audit all subdomains. Remove or secure forgotten subdomains. Implement certificate lifecycle management.",
          cvss_score: 0,
          scanner_name: "osint-crtsh",
          scanner_family: "osint",
          confidence: 0.9,
        });
      }
    }

    // 2. Shodan — Exposed services
    const shodanData = await queryShodan(domain);
    if (shodanData) {
      const subdomains = shodanData["subdomains"] as string[] | undefined;
      const totalSubdomains = (subdomains?.length ?? 0);

      if (totalSubdomains > 0) {
        findings.push({
          title: `Shodan — ${totalSubdomains} Services Exposed for ${domain}`,
          severity: "medium",
          category: "Attack Surface",
          endpoint: domain,
          cwe_id: "N/A",
          description: `Shodan shows ${totalSubdomains} services/subdomains for ${domain}. Each exposed service increases the attack surface. Review for unnecessary exposures.`,
          evidence: `Shodan domain search for ${domain}`,
          recommended_fix: "Review Shodan results for exposed services. Remove unnecessary internet-facing services. Implement proper firewall rules.",
          cvss_score: 5.0,
          scanner_name: "osint-shodan",
          scanner_family: "osint",
          confidence: 0.85,
        });
      }

      // Check for specific open ports from Shodan data
      const data = shodanData["data"] as Array<Record<string, unknown>> | undefined;
      if (data) {
        const dangerousPorts = data.filter((d: Record<string, unknown>) => {
          const port = d["port"] as number;
          const dang = [21, 22, 23, 3306, 5432, 6379, 27017, 9200, 11211];
          return dang.includes(port);
        });

        if (dangerousPorts.length > 0) {
          const portList = dangerousPorts.map((d: Record<string, unknown>) => `${d["port"]} (${d["transport"] ?? "tcp"})`);
          findings.push({
            title: `Shodan — ${dangerousPorts.length} Dangerous Open Ports Detected`,
            severity: "high",
            category: "Network Security",
            endpoint: domain,
            cwe_id: "CWE-200",
            description: `Shodan detected sensitive open ports: ${portList.join(", ")}. These should not be exposed to the internet.`,
            evidence: `Shodan port scan for ${domain}`,
            recommended_fix: "Close unused ports. Implement firewall rules. Use VPN/SSH tunneling instead of direct exposure.",
            cvss_score: 7.5,
            scanner_name: "osint-shodan-ports",
            scanner_family: "osint",
            confidence: 0.9,
          });
        }
      }
    }

    // 3. No API keys configured
    if (!SHODAN_KEY) {
      findings.push({
        title: "OSINT API Keys Not Configured — Limited Recon",
        severity: "info",
        category: "Scanner Info",
        endpoint: domain,
        cwe_id: "N/A",
        description: "No Shodan or Censys API keys configured. Set SHODAN_API_KEY and CENSYS_API_ID/CENSYS_API_SECRET environment variables for full OSINT enrichment including exposed services, subdomain enumeration, and technology fingerprinting from external sources.",
        evidence: "Environment variables not set",
        recommended_fix: "Get free API keys from shodan.io and censys.io. Set them in .env file.",
        cvss_score: 0,
        scanner_name: "osint-config",
        scanner_family: "osint",
        confidence: 1.0,
      });
    }

  } catch (err) {
    logger.warn({ err, domain }, "OSINT enrichment failed");
  }

  return findings;
}
