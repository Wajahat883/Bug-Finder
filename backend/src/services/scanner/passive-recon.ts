import * as dns from "dns/promises";
import { ScanContext, ScanFinding, safeFetch, ctxFetch } from "./types";

export async function runPassiveRecon(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Bug-Finder/PassiveRecon", message: "Running passive reconnaissance — WHOIS, ASN, IP reputation" });

  let hostname: string;
  let origin: string;
  try {
    const parsed = new URL(targetUrl);
    hostname = parsed.hostname;
    origin = parsed.origin;
  } catch {
    emit({ type: "engine_done", engine: "Bug-Finder/PassiveRecon", message: "Skipped — invalid URL" });
    return findings;
  }

  if (hostname === "localhost" || hostname.startsWith("127.") || hostname.endsWith(".replit.dev")) {
    emit({ type: "log", message: "Skipping passive recon for localhost/dev host" });
    emit({ type: "engine_done", engine: "Bug-Finder/PassiveRecon", message: "Skipped (local)" });
    return findings;
  }

  // Resolve IPs
  let ips: string[] = [];
  try {
    ips = await dns.resolve4(hostname);
    emit({ type: "log", message: `Resolved ${hostname} → ${ips.join(", ")}` });
  } catch {
    emit({ type: "log", message: `DNS resolution failed for ${hostname}` });
  }

  // RDAP/WHOIS lookup via public API
  try {
    const rdapUrl = `https://rdap.org/domain/${hostname.split(".").slice(-2).join(".")}`;
    const rdapRes = await safeFetch(rdapUrl, { headers: { Accept: "application/json" } }, 8000);
    if (rdapRes && rdapRes.status === 200) {
      const data = await rdapRes.json() as Record<string, unknown>;
      const entities = (data.entities as Array<Record<string, unknown>>) ?? [];
      const registrar = entities.find(e => (e.roles as string[] ?? []).includes("registrar"));
      const registrarName = (registrar?.vcardArray as unknown[][])?.[1]?.find?.((v: unknown[]) => (v as unknown[])[0] === "fn")?.[3] as string ?? "Unknown";
      emit({ type: "log", message: `RDAP: registrar=${registrarName}` });

      // Check for recent registration (less than 30 days old — phishing risk)
      const events = (data.events as Array<Record<string, unknown>>) ?? [];
      const regEvent = events.find(e => e.eventAction === "registration");
      if (regEvent?.eventDate) {
        const regDate = new Date(regEvent.eventDate as string);
        const ageMs = Date.now() - regDate.getTime();
        const ageDays = Math.floor(ageMs / 86400000);
        if (ageDays < 90) {
          findings.push({
            title: `Recently Registered Domain (${ageDays} days old)`,
            category: "Passive Recon",
            severity: "medium",
            endpoint: hostname,
            description: `The domain was registered only ${ageDays} days ago. Recently registered domains are frequently associated with phishing campaigns, typosquatting, or newly exposed services with immature security postures.`,
            evidence: `RDAP registration date: ${regDate.toISOString()}\nDomain age: ${ageDays} days`,
            recommended_fix: "Verify this is your domain. If testing an external target, note that recently registered domains may be malicious. Perform additional due diligence.",
            cvss_score: 4.3,
            cwe_id: "CWE-200",
            scanner_name: "Bug-Finder/PassiveRecon",
            scanner_family: "recon",
            confidence: 0.85,
          });
        }
      }
    }
  } catch {
    emit({ type: "log", message: "RDAP lookup unavailable" });
  }

  // IP geolocation and ASN lookup via free API
  for (const ip of ips.slice(0, 1)) {
    try {
      const geoRes = await safeFetch(`https://ipapi.co/${ip}/json/`, {}, 6000);
      if (geoRes && geoRes.status === 200) {
        const geo = await geoRes.json() as Record<string, unknown>;
        emit({ type: "log", message: `IP ${ip}: ASN=${geo.asn} org=${geo.org} country=${geo.country_name}` });

        // Check if hosted in high-risk jurisdiction or known hosting provider with abuse history
        const org = String(geo.org ?? "").toLowerCase();
        const highRiskOrgs = ["digitalocean", "linode", "vultr", "ovh", "hetzner"];
        const isSharedHosting = highRiskOrgs.some(o => org.includes(o));

        if (isSharedHosting) {
          findings.push({
            title: `Hosted on Shared Cloud Infrastructure: ${geo.org}`,
            category: "Passive Recon",
            severity: "info",
            endpoint: hostname,
            description: `The target is hosted on ${geo.org} (${geo.country_name}). Shared cloud hosting providers host many tenants. Ensure server-side isolation is properly configured and no sensitive data leaks via shared infrastructure.`,
            evidence: `IP: ${ip}\nASN: ${geo.asn}\nOrganization: ${geo.org}\nCountry: ${geo.country_name}\nCity: ${geo.city}`,
            recommended_fix: "Ensure proper network isolation. Use private networking for internal services. Monitor for neighbor attacks on shared infrastructure.",
            cvss_score: 2.5,
            cwe_id: "CWE-200",
            scanner_name: "Bug-Finder/PassiveRecon",
            scanner_family: "recon",
            confidence: 0.8,
          });
        }

        // Check for hosting in unexpected country
        findings.push({
          title: `Hosting Information: ${geo.org ?? "Unknown"} (${geo.country_name ?? "Unknown"})`,
          category: "Passive Recon",
          severity: "info",
          endpoint: hostname,
          description: `Target server IP ${ip} is hosted by ${geo.org} in ${geo.country_name}. This information is useful for compliance and data residency requirements.`,
          evidence: `IP: ${ip}\nASN: ${geo.asn}\nOrg: ${geo.org}\nCountry: ${geo.country_name} (${geo.country_code})\nRegion: ${geo.region}\nCity: ${geo.city}`,
          recommended_fix: "Verify hosting location meets data residency and compliance requirements (GDPR, HIPAA, etc.).",
          cvss_score: 0,
          cwe_id: "CWE-200",
          scanner_name: "Bug-Finder/PassiveRecon",
          scanner_family: "recon",
          confidence: 0.95,
        });
      }
    } catch {
      emit({ type: "log", message: `IP geolocation lookup failed for ${ip}` });
    }
  }

  // Check for sensitive files indexed by checking common passive indicators
  const sensitivePaths = [
    { path: "/crossdomain.xml", title: "Flash CrossDomain Policy Exposed", sev: "medium" as const },
    { path: "/clientaccesspolicy.xml", title: "Silverlight Client Access Policy Exposed", sev: "low" as const },
    { path: "/sitemap.xml", title: "Sitemap Exposed (Attack Surface Mapping)", sev: "info" as const },
    { path: "/.well-known/assetlinks.json", title: "Android Asset Links Exposed", sev: "info" as const },
    { path: "/humans.txt", title: "humans.txt Discloses Staff/Technology Info", sev: "info" as const },
    { path: "/package.json", title: "Node.js package.json Publicly Accessible", sev: "high" as const },
    { path: "/composer.json", title: "PHP composer.json Publicly Accessible", sev: "medium" as const },
  ];

  const base = new URL(targetUrl).origin;
  for (const check of sensitivePaths) {
    const url = `${base}${check.path}`;
    const r = await ctxFetch(ctx, url, { redirect: "follow" });
    if (r && r.status === 200) {
      const body = await r.text().catch(() => "").then(t => t.slice(0, 200));
      findings.push({
        title: check.title,
        category: "Passive Recon",
        severity: check.sev,
        endpoint: url,
        description: `${check.title} is publicly accessible. This discloses information useful for reconnaissance.`,
        evidence: `GET ${url}\nHTTP ${r.status}\nBody preview: ${body}`,
        recommended_fix: `Block or restrict access to ${check.path} at the web server level. Review what information is being disclosed.`,
        cvss_score: check.sev === "high" ? 7.5 : check.sev === "medium" ? 5.3 : check.sev === "low" ? 3.1 : 2.0,
        cwe_id: "CWE-200",
        scanner_name: "Bug-Finder/PassiveRecon",
        scanner_family: "recon",
        confidence: 0.92,
      });
      emit({ type: "log", message: `  [FOUND] ${check.path} — ${check.title}` });
    }
  }

  emit({ type: "engine_done", engine: "Bug-Finder/PassiveRecon", message: `Passive recon complete — ${findings.length} finding(s)` });
  return findings;
}
