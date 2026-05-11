import * as dns from "dns/promises";
import { ScanContext, ScanFinding } from "./types";

export async function runDnsCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Nmap/DNS", message: "Performing DNS security reconnaissance" });

  let hostname: string;
  try {
    hostname = new URL(targetUrl).hostname;
  } catch {
    emit({ type: "log", message: "Invalid URL for DNS check" });
    emit({ type: "engine_done", engine: "Nmap/DNS", message: "DNS check skipped" });
    return findings;
  }

  if (hostname === "localhost" || hostname === "127.0.0.1") {
    emit({ type: "log", message: "Skipping DNS checks for localhost" });
    emit({ type: "engine_done", engine: "Nmap/DNS", message: "DNS check skipped (localhost)" });
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
          scanner_name: "Nmap",
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
      scanner_name: "Nmap",
      scanner_family: "network",
      confidence: 0.9,
    });
    emit({ type: "log", message: `DNS resolution failed for ${hostname}` });
  }

  // Check for SPF record
  try {
    const txtRecords = await dns.resolveTxt(hostname);
    const spf = txtRecords.find(r => r.join("").includes("v=spf1"));
    if (!spf) {
      findings.push({
        title: "No SPF Record Configured",
        category: "Email Security",
        severity: "medium",
        endpoint: hostname,
        description: "No SPF (Sender Policy Framework) record was found for this domain. This allows email spoofing attacks where attackers send emails pretending to be from this domain.",
        evidence: `DNS TXT lookup for ${hostname}: No v=spf1 record found`,
        recommended_fix: "Add a TXT record: v=spf1 include:yourmailprovider.com -all",
        cvss_score: 5.3,
        cwe_id: "CWE-290",
        scanner_name: "Nmap",
        scanner_family: "network",
        confidence: 0.9,
      });
      emit({ type: "log", message: "No SPF record found" });
    } else {
      emit({ type: "log", message: `SPF record found: ${spf.join("").slice(0, 50)}` });
    }

    // Check for DMARC
    try {
      const dmarcRecords = await dns.resolveTxt(`_dmarc.${hostname}`);
      const dmarc = dmarcRecords.find(r => r.join("").includes("v=DMARC1"));
      if (!dmarc) {
        findings.push({
          title: "No DMARC Record Configured",
          category: "Email Security",
          severity: "medium",
          endpoint: hostname,
          description: "No DMARC record was found. DMARC prevents email spoofing by specifying how receivers should handle unauthenticated emails.",
          evidence: `DNS TXT lookup for _dmarc.${hostname}: No DMARC record`,
          recommended_fix: "Add DMARC: _dmarc.yourdomain.com TXT v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com",
          cvss_score: 4.3,
          cwe_id: "CWE-290",
          scanner_name: "Nmap",
          scanner_family: "network",
          confidence: 0.9,
        });
        emit({ type: "log", message: "No DMARC record found" });
      } else {
        emit({ type: "log", message: "DMARC record configured" });
      }
    } catch {
      emit({ type: "log", message: "No DMARC record found" });
    }
  } catch {
    emit({ type: "log", message: "Could not retrieve TXT records" });
  }

  emit({
    type: "engine_done",
    engine: "Nmap/DNS",
    message: `DNS check complete — ${findings.length} issue(s) found`,
  });

  return findings;
}
