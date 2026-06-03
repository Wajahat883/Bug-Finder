import * as net from "net";
import { ScanContext, ScanFinding } from "./types";

interface PortInfo {
  port: number;
  service: string;
  severity: ScanFinding["severity"];
  description: string;
  cvss: number;
  cwe: string;
}

const INTERESTING_PORTS: PortInfo[] = [
  { port: 22, service: "SSH", severity: "medium", description: "SSH port is open. Ensure key-based auth is enforced and password auth is disabled.", cvss: 5.3, cwe: "CWE-306" },
  { port: 21, service: "FTP", severity: "high", description: "FTP port is open. FTP transmits credentials in plaintext. Use SFTP/SCP instead.", cvss: 7.5, cwe: "CWE-319" },
  { port: 23, service: "Telnet", severity: "critical", description: "Telnet port is open. Telnet transmits all data including passwords in plaintext.", cvss: 9.8, cwe: "CWE-319" },
  { port: 3306, service: "MySQL", severity: "critical", description: "MySQL database port is publicly accessible. This is a major security risk.", cvss: 9.8, cwe: "CWE-284" },
  { port: 5432, service: "PostgreSQL", severity: "critical", description: "PostgreSQL port is publicly accessible. Databases should never be exposed to the internet.", cvss: 9.8, cwe: "CWE-284" },
  { port: 6379, service: "Redis", severity: "critical", description: "Redis port is open. Redis instances are often unauthenticated by default, allowing full data access.", cvss: 9.8, cwe: "CWE-284" },
  { port: 27017, service: "MongoDB", severity: "critical", description: "MongoDB port is publicly accessible. This can lead to complete data exposure or ransomware.", cvss: 9.8, cwe: "CWE-284" },
  { port: 9200, service: "Elasticsearch", severity: "critical", description: "Elasticsearch port is open. Exposed Elasticsearch clusters have led to massive data breaches.", cvss: 9.8, cwe: "CWE-284" },
  { port: 8080, service: "HTTP Alt", severity: "low", description: "Alternative HTTP port is open. May expose development services or internal admin interfaces.", cvss: 3.7, cwe: "CWE-200" },
  { port: 8443, service: "HTTPS Alt", severity: "low", description: "Alternative HTTPS port is open. Verify this is intentional.", cvss: 3.1, cwe: "CWE-200" },
  { port: 2181, service: "Zookeeper", severity: "high", description: "Zookeeper port is open. Exposed Zookeeper can allow cluster manipulation.", cvss: 8.1, cwe: "CWE-284" },
  { port: 9092, service: "Kafka", severity: "high", description: "Kafka broker port is open. Unauthenticated Kafka access allows reading/writing all messages.", cvss: 8.1, cwe: "CWE-284" },
  { port: 5601, service: "Kibana", severity: "high", description: "Kibana dashboard port is open. This can expose sensitive log data.", cvss: 7.5, cwe: "CWE-284" },
  { port: 4444, service: "Metasploit", severity: "critical", description: "Port 4444 is open — commonly used for reverse shells.", cvss: 9.8, cwe: "CWE-284" },
  { port: 8888, service: "Jupyter Notebook", severity: "critical", description: "Port 8888 is open — commonly used by Jupyter Notebook which may allow arbitrary code execution.", cvss: 9.8, cwe: "CWE-284" },
];

function grabBanner(host: string, port: number, timeoutMs = 4000): Promise<{ open: boolean; banner: string }> {
  return new Promise(resolve => {
    const socket = new net.Socket();
    let resolved = false;
    let banner = "";

    const done = (open: boolean) => {
      if (resolved) return;
      resolved = true;
      socket.destroy();
      resolve({ open, banner: banner.slice(0, 200).trim() });
    };

    socket.setTimeout(timeoutMs);
    socket.once("connect", () => {
      // Send a generic probe — many services respond with a banner immediately
      socket.write("HEAD / HTTP/1.0\r\n\r\n");
    });
    socket.on("data", (chunk: Buffer) => {
      banner += chunk.toString("utf8", 0, 200);
      if (banner.length >= 200) done(true);
    });
    socket.once("error", () => done(false));
    socket.once("timeout", () => done(banner.length > 0));
    socket.once("end", () => done(true));

    try {
      socket.connect(port, host);
    } catch {
      done(false);
    }
  });
}

export async function runPortScan(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, profile } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Bug-Finder/Ports", message: "Scanning for open dangerous ports" });

  let host: string;
  try {
    host = new URL(targetUrl).hostname;
  } catch {
    emit({ type: "log", message: "Invalid target URL for port scan" });
    emit({ type: "engine_done", engine: "Bug-Finder/Ports", message: "Port scan skipped" });
    return findings;
  }

  // Skip port scanning for localhost (common in development)
  if (host === "localhost" || host === "127.0.0.1") {
    emit({ type: "log", message: "Skipping port scan for local/dev host" });
    emit({ type: "engine_done", engine: "Bug-Finder/Ports", message: "Port scan skipped (local host)" });
    return findings;
  }

  const budget = profile === "quick" ? 6 : profile === "standard" ? 10 : INTERESTING_PORTS.length;
  const portsToCheck = INTERESTING_PORTS.slice(0, budget);

  emit({ type: "log", message: `Checking ${portsToCheck.length} ports on ${host}...` });

  const results = await Promise.all(
    portsToCheck.map(async (p) => ({
      info: p,
      ...(await grabBanner(host, p.port)),
    }))
  );

  for (const { info, open, banner } of results) {
    if (open) {
      // Extract version from banner for CVE correlation
      const versionMatch = banner.match(/[\w\-]+\/(\d+[\.\d]+)/);
      const detectedVersion = versionMatch?.[1];
      const bannerLine = banner ? `\nBanner: ${banner}` : "";
      const versionLine = detectedVersion ? `\nDetected version from banner: ${detectedVersion}` : "";

      findings.push({
        title: `Open Port: ${info.port}/${info.service}${detectedVersion ? ` (v${detectedVersion})` : ""}`,
        category: "Network Security",
        severity: info.severity,
        endpoint: `${host}:${info.port}`,
        description: info.description + (detectedVersion ? ` Detected version: ${detectedVersion}.` : ""),
        evidence: `TCP connect to ${host}:${info.port} — SUCCESS\nService: ${info.service}${bannerLine}${versionLine}`,
        recommended_fix: `Firewall port ${info.port} to restrict access. Only expose services that must be publicly accessible.`,
        cvss_score: info.cvss,
        cwe_id: info.cwe,
        scanner_name: "Bug-Finder/Port-Scanner",
        scanner_family: "network",
        confidence: 0.98,
      });
      emit({ type: "log", message: `  [OPEN] Port ${info.port}/${info.service}${banner ? ` — banner: ${banner.slice(0, 60)}` : ""}` });
    } else {
      emit({ type: "log", message: `  Port ${info.port}/${info.service} — closed` });
    }
  }

  emit({
    type: "engine_done",
    engine: "Bug-Finder/Ports",
    message: `Port scan complete — ${findings.length} open dangerous port(s) found`,
  });

  return findings;
}
