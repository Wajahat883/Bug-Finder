import * as dns from "dns/promises";
import { ScanContext, ScanFinding, safeFetch } from "./types";
import { getRootRoot, getRootDomain } from "./normalize-engine";

// Known services vulnerable to subdomain takeover — fingerprint is what a dangling CNAME shows
const TAKEOVER_FINGERPRINTS: Array<{ service: string; cnameSuffix: string; fingerprint: string; severity: ScanFinding["severity"] }> = [
  { service: "GitHub Pages", cnameSuffix: ".github.io", fingerprint: "There isn't a GitHub Pages site here", severity: "high" },
  { service: "Heroku", cnameSuffix: ".herokuapp.com", fingerprint: "No such app", severity: "high" },
  { service: "Fastly", cnameSuffix: ".fastly.net", fingerprint: "Fastly error: unknown domain", severity: "high" },
  { service: "Shopify", cnameSuffix: ".myshopify.com", fingerprint: "Sorry, this shop is currently unavailable", severity: "high" },
  { service: "Tumblr", cnameSuffix: ".tumblr.com", fingerprint: "There's nothing here", severity: "high" },
  { service: "WordPress", cnameSuffix: ".wordpress.com", fingerprint: "Do you want to register", severity: "medium" },
  { service: "Zendesk", cnameSuffix: ".zendesk.com", fingerprint: "Help Center Closed", severity: "high" },
  { service: "Surge.sh", cnameSuffix: ".surge.sh", fingerprint: "project not found", severity: "high" },
  { service: "Netlify", cnameSuffix: ".netlify.app", fingerprint: "Not Found - Request ID", severity: "high" },
  { service: "Azure", cnameSuffix: ".azurewebsites.net", fingerprint: "404 Web Site not found", severity: "high" },
  { service: "AWS CloudFront", cnameSuffix: ".cloudfront.net", fingerprint: "Bad request", severity: "medium" },
  { service: "S3 Bucket", cnameSuffix: ".s3.amazonaws.com", fingerprint: "NoSuchBucket", severity: "critical" },
];

export async function runDnsCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Bug-Finder/DNS", message: "Performing DNS security reconnaissance" });

  let hostname: string;
  try {
    hostname = new URL(targetUrl).hostname;
  } catch {
    emit({ type: "log", message: "Invalid URL for DNS check" });
    emit({ type: "engine_done", engine: "Bug-Finder/DNS", message: "DNS check skipped" });
    return findings;
  }

  if (hostname === "localhost" || hostname === "127.0.0.1") {
    emit({ type: "log", message: "Skipping DNS checks for localhost" });
    emit({ type: "engine_done", engine: "Bug-Finder/DNS", message: "DNS check skipped (localhost)" });
    return findings;
  }

  // Check DNS A records
  try {
    const addresses = await dns.resolve4(hostname);
    emit({ type: "log", message: `A records: ${addresses.join(", ")}` });

    // Check if it's a private IP range
    for (const ip of addresses) {
      const parts = ip.split(".").map(Number);
      const isPrivate =
        parts[0] === 10 ||
        (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
        (parts[0] === 192 && parts[1] === 168) ||
        parts[0] === 127;

      if (isPrivate) {
        findings.push({
          title: "Internal/Private IP Address in DNS Record",
          category: "Information Disclosure",
          severity: "medium",
          endpoint: hostname,
          description: `The DNS A record for ${hostname} resolves to a private IP address (${ip}). This may indicate a DNS misconfiguration or expose internal network topology.`,
          evidence: `DNS A record: ${hostname} → ${ip}`,
          recommended_fix: "Ensure public-facing services only resolve to public IP addresses. Review your DNS configuration.",
          cvss_score: 5.3,
          cwe_id: "CWE-200",
          scanner_name: "Bug-Finder/Port-Scanner",
          scanner_family: "network",
          confidence: 0.9,
        });
        emit({ type: "log", message: `  Private IP detected: ${ip}` });
      }
    }
  } catch {
    findings.push({
      title: "DNS Resolution Failure",
      category: "Availability",
      severity: "info",
      endpoint: hostname,
      description: `The hostname ${hostname} could not be resolved via DNS. The target may be unreachable.`,
      evidence: `DNS lookup for ${hostname} failed`,
      recommended_fix: "Verify the target URL is correct and DNS is properly configured.",
      cvss_score: 0,
      cwe_id: "CWE-200",
      scanner_name: "Bug-Finder/Port-Scanner",
      scanner_family: "network",
      confidence: 0.9,
    });
    emit({ type: "log", message: `DNS resolution failed for ${hostname}` });
  }

  // Check for SPF record — always on the ROOT (apex) domain, not www subdomain.
  // SPF records live at the organizational domain level (RFC 7208 §3.1).
  // Checking www.example.com instead of example.com produces false negatives.
  const rootDomain = getRootRoot(hostname);
  const spfDomain = rootDomain !== hostname ? rootDomain : hostname;
  const spfLabel = spfDomain !== hostname ? `root domain ${spfDomain}` : hostname;

  try {
    const txtRecords = await dns.resolveTxt(spfDomain);
    const spf = txtRecords.find(r => r.join("").toLowerCase().includes("v=spf1"));
    if (!spf) {
      findings.push({
        title: "No SPF Record Configured",
        category: "Email Security",
        severity: "medium",
        endpoint: spfDomain,
        description: `No SPF (Sender Policy Framework) record was found for the root domain ${spfDomain}${spfDomain !== hostname ? ` (resolved from ${hostname})` : ""}. This allows email spoofing attacks.`,
        evidence: `DNS TXT lookup for ${spfDomain}: No v=spf1 record found`,
        recommended_fix: "Add a TXT record at the root domain: v=spf1 include:yourmailprovider.com -all",
        cvss_score: 5.3,
        cwe_id: "CWE-290",
        scanner_name: "Bug-Finder/DNS",
        scanner_family: "network",
        confidence: 0.9,
      });
      emit({ type: "log", message: `No SPF record found for ${spfDomain}` });
    } else {
      emit({ type: "log", message: `SPF record found at ${spfDomain}: ${spf.join("").slice(0, 50)}` });
    }

    // Check for DMARC — also on the root (organizational) domain
    try {
      const dmarcRecords = await dns.resolveTxt(`_dmarc.${spfDomain}`);
      const dmarc = dmarcRecords.find(r => r.join("").toLowerCase().includes("v=dmarc1"));
      if (!dmarc) {
        findings.push({
          title: "No DMARC Record Configured",
          category: "Email Security",
          severity: "medium",
          endpoint: spfDomain,
          description: `No DMARC record was found for the root domain ${spfDomain}${spfDomain !== hostname ? ` (resolved from ${hostname})` : ""}. DMARC prevents email spoofing.`,
          evidence: `DNS TXT lookup for _dmarc.${spfDomain}: No DMARC record`,
          recommended_fix: "Add DMARC: _dmarc.yourdomain.com TXT v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com",
          cvss_score: 4.3,
          cwe_id: "CWE-290",
          scanner_name: "Bug-Finder/DNS",
          scanner_family: "network",
          confidence: 0.9,
        });
        emit({ type: "log", message: `No DMARC record found for ${spfDomain}` });
      } else {
        emit({ type: "log", message: "DMARC record configured" });
      }
    } catch {
      emit({ type: "log", message: `No DMARC record found for ${spfDomain}` });
    }
  } catch {
    emit({ type: "log", message: "Could not retrieve TXT records" });
  }

  // ── CNAME subdomain takeover check ─────────────────────────────────────────
  // Check if CNAME points to a service that shows "unclaimed" fingerprint
  try {
    const cnames = await dns.resolveCname(hostname).catch(() => [] as string[]);
    for (const cname of cnames) {
      const matched = TAKEOVER_FINGERPRINTS.find(fp => cname.toLowerCase().endsWith(fp.cnameSuffix));
      if (!matched) continue;

      // Actually fetch the CNAME target URL to check for the takeover fingerprint
      const cnameUrl = `https://${hostname}`;
      const cnameRes = await safeFetch(cnameUrl, {}, 8000);
      const cnameBody = cnameRes ? await cnameRes.text().catch(() => "") : "";

      if (cnameBody.toLowerCase().includes(matched.fingerprint.toLowerCase())) {
        findings.push({
          title: `Subdomain Takeover via ${matched.service}: ${hostname}`,
          category: "Subdomain Takeover",
          severity: matched.severity,
          endpoint: `https://${hostname}`,
          description: `The subdomain ${hostname} has a CNAME record pointing to ${cname} (${matched.service}), but the target service is unclaimed. An attacker can register this ${matched.service} resource and serve arbitrary content from your domain — enabling session hijacking, phishing, and cookie theft.`,
          evidence: [
            `CNAME: ${hostname} → ${cname}`,
            `Service: ${matched.service}`,
            `Takeover fingerprint confirmed: "${matched.fingerprint}"`,
            `GET ${cnameUrl}`,
            `HTTP ${cnameRes?.status ?? "N/A"} — response body contains unclaimed fingerprint`,
            `Response snippet: ${cnameBody.slice(0, 300)}`,
          ].join("\n"),
          recommended_fix: `Remove the dangling CNAME record for ${hostname} immediately, or claim the ${matched.service} resource. Implement a monitoring process for CNAME records pointing to third-party services.`,
          cvss_score: matched.severity === "critical" ? 9.3 : 8.2,
          cwe_id: "CWE-350",
          scanner_name: "Bug-Finder/DNS",
          scanner_family: "network",
          confidence: 0.95,
        });
        emit({ type: "log", message: `  [TAKEOVER CONFIRMED] ${hostname} → ${cname} (${matched.service}) — fingerprint matched` });
      } else {
        emit({ type: "log", message: `  CNAME ${hostname} → ${cname} (${matched.service}) — fingerprint not matched, no takeover` });
      }
    }
  } catch {
    emit({ type: "log", message: "CNAME resolution failed — skipping takeover check" });
  }

  emit({
    type: "engine_done",
    engine: "Bug-Finder/DNS",
    message: `DNS check complete — ${findings.length} issue(s) found`,
  });

  return findings;
}
