import * as tls from "node:tls";
import { ScanContext, ScanFinding, ctxFetch, safeFetch } from "./types";

interface TlsSocketInfo {
  protocol: string | null;
  cipher: tls.CipherNameAndProtocol | null;
  cert: tls.PeerCertificate | null;
  error?: string;
}

function checkTlsSocket(hostname: string, port: number, maxVersion?: tls.SecureVersion, minVersion?: tls.SecureVersion): Promise<TlsSocketInfo> {
  return new Promise((resolve) => {
    const opts: tls.ConnectionOptions = {
      host: hostname, port, rejectUnauthorized: false, timeout: 8000, servername: hostname,
    };
    if (maxVersion) opts.maxVersion = maxVersion;
    if (minVersion) opts.minVersion = minVersion;

    const socket = tls.connect(opts, () => {
      const protocol = socket.getProtocol?.() ?? null;
      const cipher = socket.getCipher();
      const cert = socket.getPeerCertificate();
      socket.destroy();
      resolve({ protocol, cipher, cert });
    });
    socket.on("error", (err) => resolve({ protocol: null, cipher: null, cert: null, error: err.message }));
    socket.on("timeout", () => { socket.destroy(); resolve({ protocol: null, cipher: null, cert: null, error: "timeout" }); });
  });
}

// Attempt forced TLS downgrade — connect with maxVersion set to an old protocol.
// Returns the protocol that was actually negotiated (or null if rejected).
async function checkTlsDowngrade(hostname: string, port: number, maxVersion: tls.SecureVersion): Promise<string | null> {
  const result = await checkTlsSocket(hostname, port, maxVersion, maxVersion);
  if (result.error) return null; // Connection refused = downgrade blocked
  return result.protocol;
}

// Known weak ciphers
const WEAK_CIPHERS = [
  "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON",
  "RC4-SHA", "DES-CBC3-SHA", "EXP-", "ADH-", "AECDH-",
];

export async function runTlsCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, profile } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Bug-Finder/TLS", message: "Checking TLS configuration (socket-level)" });

  const parsed = new URL(targetUrl);
  const isHttps = parsed.protocol === "https:";
  const hostname = parsed.hostname;
  const port = parseInt(parsed.port || (isHttps ? "443" : "80"));

  // ── 1. HTTP → HTTPS redirect check ───────────────────────────────────────
  if (!isHttps) {
    const httpsUrl = targetUrl.replace(/^http:/, "https:");
    const [httpsRes, httpRes] = await Promise.all([
      safeFetch(httpsUrl, { redirect: "manual" }),
      safeFetch(targetUrl, { redirect: "manual" }),
    ]);

    if (!httpsRes) {
      findings.push({
        title: "HTTPS Not Available",
        category: "TLS/Transport",
        severity: "high",
        endpoint: targetUrl,
        description: "The target does not support HTTPS. All traffic is transmitted in plaintext, including credentials and sensitive data.",
        evidence: `Attempted HTTPS at ${httpsUrl} — no response.\nHTTP response: ${httpRes?.status ?? "unreachable"}`,
        recommended_fix: "Enable TLS 1.2+ on the server. Obtain a certificate from Let's Encrypt (free) or a commercial CA.",
        cvss_score: 7.5,
        cwe_id: "CWE-319",
        scanner_name: "Bug-Finder/TLS",
        scanner_family: "network",
        confidence: 0.95,
      });
    }

    if (httpRes && httpRes.status === 200) {
      findings.push({
        title: "HTTP Not Redirected to HTTPS",
        category: "TLS/Transport",
        severity: "medium",
        endpoint: targetUrl,
        description: "The server accepts plaintext HTTP connections without redirecting to HTTPS. Attackers on the network can intercept or modify traffic.",
        evidence: `GET ${targetUrl}\nHTTP/1.1 ${httpRes.status} ${httpRes.statusText}\nLocation: [missing — no redirect]`,
        recommended_fix: "Add a 301 permanent redirect from HTTP to HTTPS: return 301 https://$host$request_uri;",
        cvss_score: 5.3,
        cwe_id: "CWE-319",
        scanner_name: "Bug-Finder/TLS",
        scanner_family: "network",
        confidence: 0.92,
      });
    }
  }

  // ── 2. Real TLS socket-level checks ──────────────────────────────────────
  if (isHttps || hostname !== "localhost") {
    const tlsPort = isHttps ? port : 443;
    emit({ type: "log", message: `TLS socket check on ${hostname}:${tlsPort}` });
    const tlsInfo = await checkTlsSocket(hostname, tlsPort);

    if (tlsInfo.error) {
      emit({ type: "log", message: `TLS socket error: ${tlsInfo.error}` });
    } else {
      const proto = tlsInfo.protocol ?? "unknown";
      emit({ type: "log", message: `TLS protocol: ${proto} | Cipher: ${tlsInfo.cipher?.name ?? "unknown"}` });

      // Check for deprecated TLS versions
      if (proto === "TLSv1" || proto === "TLSv1.0") {
        findings.push({
          title: "TLS 1.0 Enabled — Deprecated Protocol",
          category: "TLS/Transport",
          severity: "high",
          endpoint: targetUrl,
          description: "The server supports TLS 1.0, which is vulnerable to BEAST and POODLE attacks. PCI-DSS 4.0 requires TLS 1.2 minimum.",
          evidence: `TLS socket negotiated: ${proto}\nServer: ${hostname}:${tlsPort}\nCipher: ${tlsInfo.cipher?.name ?? "unknown"}`,
          recommended_fix: "Disable TLS 1.0 and 1.1. Configure minimum TLS version to 1.2:\nssl_protocols TLSv1.2 TLSv1.3;",
          cvss_score: 6.8,
          cwe_id: "CWE-326",
          scanner_name: "Bug-Finder/TLS",
          scanner_family: "network",
          confidence: 0.98,
        });
      } else if (proto === "TLSv1.1") {
        findings.push({
          title: "TLS 1.1 Enabled — Deprecated Protocol",
          category: "TLS/Transport",
          severity: "medium",
          endpoint: targetUrl,
          description: "TLS 1.1 is deprecated (RFC 8996). It lacks support for modern AEAD cipher suites.",
          evidence: `Negotiated: ${proto} on ${hostname}:${tlsPort}`,
          recommended_fix: "Disable TLS 1.1. Allow only TLS 1.2 and TLS 1.3.",
          cvss_score: 5.3,
          cwe_id: "CWE-326",
          scanner_name: "Bug-Finder/TLS",
          scanner_family: "network",
          confidence: 0.95,
        });
      }

      // Check for weak ciphers
      const cipherName = (tlsInfo.cipher?.name ?? "").toUpperCase();
      const weakMatch = WEAK_CIPHERS.find(w => cipherName.includes(w));
      if (weakMatch) {
        findings.push({
          title: `Weak Cipher Suite in Use: ${tlsInfo.cipher?.name}`,
          category: "TLS/Transport",
          severity: "high",
          endpoint: targetUrl,
          description: `The TLS negotiation selected a weak cipher suite (${tlsInfo.cipher?.name}). This cipher provides inadequate cryptographic protection.`,
          evidence: `Cipher negotiated: ${tlsInfo.cipher?.name}\nProtocol: ${proto}\nWeak pattern matched: ${weakMatch}`,
          recommended_fix: "Configure strong cipher suites only:\nssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305';",
          cvss_score: 7.4,
          cwe_id: "CWE-327",
          scanner_name: "Bug-Finder/TLS",
          scanner_family: "network",
          confidence: 0.95,
        });
      }

      // ── TLS downgrade attack tests — force old protocol negotiation ──────
      // Even if the server negotiated TLS 1.2+, it may still ACCEPT connections
      // that force TLS 1.0 or 1.1. We test by connecting with maxVersion set.
      if (profile !== "quick") {
        const downgradeTests: Array<{ version: tls.SecureVersion; label: string; cve: string; cvss: number }> = [
          { version: "TLSv1", label: "TLS 1.0", cve: "CVE-2011-3389 (BEAST)", cvss: 6.8 },
          { version: "TLSv1.1", label: "TLS 1.1", cve: "RFC 8996 deprecation", cvss: 5.3 },
        ];
        for (const dt of downgradeTests) {
          const negotiated = await checkTlsDowngrade(hostname, tlsPort, dt.version);
          if (negotiated && (negotiated === "TLSv1" || negotiated === "TLSv1.1")) {
            findings.push({
              title: `TLS Downgrade Attack Possible — Server Accepts Forced ${dt.label}`,
              category: "TLS/Transport",
              severity: dt.cvss >= 7 ? "high" : "medium",
              endpoint: targetUrl,
              description: `The server accepted a forced ${dt.label} connection even though it may normally negotiate higher versions. An active network attacker (MITM) can force clients to downgrade to ${dt.label} and exploit known weaknesses (${dt.cve}).`,
              evidence: [
                `Downgrade test: connected to ${hostname}:${tlsPort} with maxVersion=${dt.version}`,
                `Negotiated protocol: ${negotiated}`,
                `Result: Server ACCEPTED ${dt.label} — downgrade is possible`,
                `Normal negotiated: ${proto}`,
              ].join("\n"),
              recommended_fix: `Configure the server to reject connections requesting ${dt.label} or older:\n  ssl_protocols TLSv1.2 TLSv1.3;\nDisabling older protocols server-side prevents forced downgrade even when the client requests it.`,
              cvss_score: dt.cvss,
              cwe_id: "CWE-326",
              scanner_name: "Bug-Finder/TLS",
              scanner_family: "network",
              confidence: 0.97,
            });
            emit({ type: "log", message: `  [TLS DOWNGRADE] Server accepted forced ${dt.label} on ${hostname}:${tlsPort}` });
          } else {
            emit({ type: "log", message: `  TLS downgrade to ${dt.label}: rejected (good)` });
          }
        }
      }

      // Check certificate expiry
      if (tlsInfo.cert && tlsInfo.cert.valid_to) {
        const expiresAt = new Date(tlsInfo.cert.valid_to);
        const daysLeft = Math.floor((expiresAt.getTime() - Date.now()) / 86400000);

        if (daysLeft < 0) {
          findings.push({
            title: "TLS Certificate Expired",
            category: "TLS/Transport",
            severity: "critical",
            endpoint: targetUrl,
            description: `The TLS certificate expired ${Math.abs(daysLeft)} days ago. Browsers will show a security error and refuse to connect.`,
            evidence: `Subject: ${tlsInfo.cert.subject?.CN ?? "unknown"}\nExpired: ${tlsInfo.cert.valid_to}\nDays expired: ${Math.abs(daysLeft)}`,
            recommended_fix: "Renew the TLS certificate immediately. Use Let's Encrypt with auto-renewal to prevent future expirations.",
            cvss_score: 9.1,
            cwe_id: "CWE-298",
            scanner_name: "Bug-Finder/TLS",
            scanner_family: "network",
            confidence: 1.0,
          });
        } else if (daysLeft < 14) {
          findings.push({
            title: `TLS Certificate Expiring in ${daysLeft} Days`,
            category: "TLS/Transport",
            severity: "high",
            endpoint: targetUrl,
            description: `The TLS certificate will expire in ${daysLeft} days. Failure to renew will cause browsers to reject connections.`,
            evidence: `Subject: ${tlsInfo.cert.subject?.CN ?? "unknown"}\nExpires: ${tlsInfo.cert.valid_to}\nDays remaining: ${daysLeft}`,
            recommended_fix: "Renew the certificate immediately. Configure auto-renewal with certbot: certbot renew --pre-hook 'nginx -t'",
            cvss_score: 7.5,
            cwe_id: "CWE-298",
            scanner_name: "Bug-Finder/TLS",
            scanner_family: "network",
            confidence: 1.0,
          });
        } else if (daysLeft < 30) {
          findings.push({
            title: `TLS Certificate Expiring Soon (${daysLeft} Days)`,
            category: "TLS/Transport",
            severity: "medium",
            endpoint: targetUrl,
            description: `TLS certificate expires in ${daysLeft} days. Plan renewal soon.`,
            evidence: `Expires: ${tlsInfo.cert.valid_to} | Days left: ${daysLeft}`,
            recommended_fix: "Schedule certificate renewal. Enable auto-renewal with certbot or your CA's ACME client.",
            cvss_score: 4.3,
            cwe_id: "CWE-298",
            scanner_name: "Bug-Finder/TLS",
            scanner_family: "network",
            confidence: 1.0,
          });
        } else {
          emit({ type: "log", message: `Certificate valid: ${daysLeft} days remaining (${tlsInfo.cert.valid_to})` });
        }

        // Check for self-signed certificate
        const subject = tlsInfo.cert.subject?.CN ?? "";
        const issuer = tlsInfo.cert.issuer?.CN ?? "";
        if (subject && issuer && subject === issuer) {
          findings.push({
            title: "Self-Signed TLS Certificate",
            category: "TLS/Transport",
            severity: "medium",
            endpoint: targetUrl,
            description: "The server uses a self-signed TLS certificate. Clients cannot verify the server's identity, enabling MITM attacks.",
            evidence: `Subject CN: ${subject}\nIssuer CN: ${issuer}\nSelf-signed: subject equals issuer`,
            recommended_fix: "Replace the self-signed certificate with one from a trusted CA. Let's Encrypt provides free trusted certificates.",
            cvss_score: 5.9,
            cwe_id: "CWE-295",
            scanner_name: "Bug-Finder/TLS",
            scanner_family: "network",
            confidence: 0.95,
          });
        }
      }
    }
  }

  // ── 3. HSTS header check ──────────────────────────────────────────────────
  const res = await ctxFetch(ctx, targetUrl);
  if (res) {
    const hsts = res.headers.get("strict-transport-security");
    if (!hsts && isHttps) {
      findings.push({
        title: "Missing HTTP Strict-Transport-Security (HSTS) Header",
        category: "TLS/Transport",
        severity: "medium",
        endpoint: targetUrl,
        description: "No HSTS header is set. Browsers will not enforce HTTPS on subsequent visits, leaving users vulnerable to SSL stripping.",
        evidence: `GET ${targetUrl}\nStrict-Transport-Security: [MISSING]\n\nFull response headers:\n${[...res.headers.entries()].map(([k, v]) => `${k}: ${v}`).join("\n")}`,
        recommended_fix: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        cvss_score: 5.3,
        cwe_id: "CWE-319",
        scanner_name: "Bug-Finder/TLS",
        scanner_family: "network",
        confidence: 0.95,
      });
    } else if (hsts) {
      if (!hsts.includes("includeSubDomains")) {
        findings.push({
          title: "HSTS Missing includeSubDomains Directive",
          category: "TLS/Transport",
          severity: "low",
          endpoint: targetUrl,
          description: "HSTS does not cover subdomains, allowing attackers to downgrade subdomain connections to HTTP.",
          evidence: `Strict-Transport-Security: ${hsts}\nMissing: includeSubDomains`,
          recommended_fix: "Update to: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
          cvss_score: 3.1,
          cwe_id: "CWE-319",
          scanner_name: "Bug-Finder/TLS",
          scanner_family: "network",
          confidence: 0.9,
        });
      }
      const maxAge = hsts.match(/max-age=(\d+)/);
      if (maxAge && parseInt(maxAge[1]) < 2592000) {
        findings.push({
          title: "HSTS max-age Too Short",
          category: "TLS/Transport",
          severity: "low",
          endpoint: targetUrl,
          description: `HSTS max-age is ${maxAge[1]} seconds (< 30 days). HSTS preload requires at least 1 year (31536000 seconds).`,
          evidence: `Strict-Transport-Security: ${hsts}`,
          recommended_fix: "Set max-age to at least 31536000 (1 year) for HSTS preload eligibility.",
          cvss_score: 3.1,
          cwe_id: "CWE-319",
          scanner_name: "Bug-Finder/TLS",
          scanner_family: "network",
          confidence: 0.95,
        });
      }
      emit({ type: "log", message: `HSTS: ${hsts.slice(0, 80)}` });
    }
  }

  emit({
    type: "engine_done",
    engine: "Bug-Finder/TLS",
    message: `TLS check complete — ${findings.length} issue(s) found`,
  });

  return findings;
}
