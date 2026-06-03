import { ScanContext, ScanFinding, ctxFetch } from "./types";

const GRPC_PORTS = [50051, 50052, 9090, 9091, 8090];
const GRPC_WEB_PATHS = ["/grpc", "/grpc-web", "/api/grpc"];

// gRPC-Web framing: 5-byte header (1 byte flags, 4 bytes length) + proto message body.
// For an empty ListServices request the proto body is just the varint field 1 = "" (empty string = 0x0a 0x00).
function grpcWebFrame(protoBody: Uint8Array): Uint8Array {
  const frame = new Uint8Array(5 + protoBody.length);
  frame[0] = 0; // not compressed
  const len = protoBody.length;
  frame[1] = (len >> 24) & 0xff;
  frame[2] = (len >> 16) & 0xff;
  frame[3] = (len >> 8) & 0xff;
  frame[4] = len & 0xff;
  frame.set(protoBody, 5);
  return frame;
}

// Decode a gRPC-Web framed response body — returns the first message payload bytes
function grpcWebDecode(buf: Uint8Array): Uint8Array | null {
  if (buf.length < 5) return null;
  const flags = buf[0]!;
  if (flags & 0x80) return null; // trailer frame
  const len = (buf[1]! << 24) | (buf[2]! << 16) | (buf[3]! << 8) | buf[4]!;
  if (buf.length < 5 + len) return null;
  return buf.slice(5, 5 + len);
}

// Very small protobuf decoder — reads a varint from bytes at offset
function readVarint(bytes: Uint8Array, offset: number): { value: number; next: number } {
  let value = 0, shift = 0;
  while (offset < bytes.length) {
    const b = bytes[offset++]!;
    value |= (b & 0x7f) << shift;
    shift += 7;
    if (!(b & 0x80)) break;
  }
  return { value, next: offset };
}

// Extract length-delimited string fields from a flat proto message (field type 2)
function extractStrings(bytes: Uint8Array): string[] {
  const results: string[] = [];
  let i = 0;
  while (i < bytes.length) {
    const tag = readVarint(bytes, i);
    i = tag.next;
    const wireType = tag.value & 0x7;
    const fieldNum = tag.value >> 3;
    if (wireType === 2) {
      const lenR = readVarint(bytes, i);
      i = lenR.next;
      const strBytes = bytes.slice(i, i + lenR.value);
      i += lenR.value;
      try { results.push(new TextDecoder().decode(strBytes)); } catch { /* skip */ }
    } else if (wireType === 0) {
      const v = readVarint(bytes, i); i = v.next; void fieldNum;
    } else if (wireType === 5) {
      i += 4;
    } else if (wireType === 1) {
      i += 8;
    } else {
      break; // unknown wire type — stop
    }
  }
  return results;
}

// Build a ServerReflectionRequest proto with host="" (list all services)
// Field 1 (host): tag=0x0a, value="" → [0x0a, 0x00]
// Field 3 (list_services): tag=0x1a, value="" → [0x1a, 0x00]
function buildListServicesProto(): Uint8Array {
  return new Uint8Array([0x0a, 0x00, 0x1a, 0x00]);
}

// Build a ServerReflectionRequest to get FileDescriptorByFilename
// Field 1 = host "", Field 4 = file_by_filename string
function buildFileBySymbolProto(symbol: string): Uint8Array {
  const symbolBytes = new TextEncoder().encode(symbol);
  const field1 = [0x0a, 0x00]; // host = ""
  const field4Tag = [0x22]; // field 4, wire type 2
  const lenVarint = symbol.length < 128 ? [symbol.length] : [0x80 | (symbol.length & 0x7f), symbol.length >> 7];
  return new Uint8Array([...field1, ...field4Tag, ...lenVarint, ...symbolBytes]);
}

// Common method-level injection payloads for gRPC string fields
const GRPC_INJECTION_PAYLOADS = [
  { name: "SQLi quote", value: "' OR '1'='1" },
  { name: "XSS tag", value: "<xssgrpc1337>" },
  { name: "path traversal", value: "../../etc/passwd" },
  { name: "null byte", value: "\x00admin" },
];

export async function runGrpcCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, profile } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Bug-Finder/gRPC", message: "Testing gRPC: reflection enumeration, method injection, auth bypass" });

  const base = new URL(targetUrl).origin;
  const hostname = new URL(targetUrl).hostname;

  if (hostname === "localhost" || hostname.startsWith("127.")) {
    emit({ type: "log", message: "Skipping gRPC port scan for local/dev host" });
    emit({ type: "engine_done", engine: "Bug-Finder/gRPC", message: "Skipped (local host)" });
    return findings;
  }

  // ── 1. Discover gRPC-Web endpoints ───────────────────────────────────────
  const grpcEndpoints: string[] = [];

  for (const path of GRPC_WEB_PATHS) {
    const url = `${base}${path}`;
    const r = await ctxFetch(ctx, url, {
      method: "POST",
      headers: {
        "Content-Type": "application/grpc-web+proto",
        "X-Grpc-Web": "1",
        "Accept": "application/grpc-web+proto",
      },
      body: grpcWebFrame(new Uint8Array([0])) as unknown as BodyInit,
    });

    if (!r) continue;
    const ct = r.headers.get("content-type") ?? "";
    const grpcStatus = r.headers.get("grpc-status") ?? r.headers.get("x-grpc-status") ?? "";

    if (ct.includes("grpc") || grpcStatus !== "") {
      grpcEndpoints.push(url);
      findings.push({
        title: "gRPC-Web Endpoint Detected",
        category: "API Security",
        severity: "info",
        endpoint: url,
        description: `A gRPC-Web endpoint was found at ${url}. gRPC services require specialized security testing. Ensure authentication, authorization, and input validation are enforced on all gRPC methods.`,
        evidence: `POST ${url}\nContent-Type: application/grpc-web+proto\nHTTP ${r.status}\ngrpc-status: ${grpcStatus || "[none]"}\ncontent-type: ${ct}`,
        recommended_fix: "Implement authentication for all gRPC services. Enable TLS. Disable gRPC server reflection in production. Apply input validation on all message fields.",
        cvss_score: 3.7,
        cwe_id: "CWE-284",
        scanner_name: "Bug-Finder/gRPC",
        scanner_family: "api",
        confidence: 0.85,
      });
      emit({ type: "log", message: `gRPC-Web endpoint found: ${url}` });
    }
  }

  // ── 2. Server Reflection — enumerate all services and methods ────────────
  const discoveredServices: string[] = [];

  for (const grpcBase of grpcEndpoints) {
    const reflectUrl = `${grpcBase}/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo`;
    const listProto = buildListServicesProto();
    const frame = grpcWebFrame(listProto);

    const reflectR = await ctxFetch(ctx, reflectUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/grpc-web+proto",
        "X-Grpc-Web": "1",
        "Accept": "application/grpc-web+proto",
      },
      body: frame as unknown as BodyInit,
    });

    if (!reflectR || reflectR.status !== 200) continue;

    // Parse response binary
    const buf = await reflectR.arrayBuffer().catch(() => null);
    if (!buf) continue;
    const bytes = new Uint8Array(buf);
    const payload = grpcWebDecode(bytes);
    const serviceNames = payload ? extractStrings(payload).filter(s => s.includes(".")) : [];

    if (serviceNames.length > 0) {
      discoveredServices.push(...serviceNames);

      findings.push({
        title: "gRPC Server Reflection Enabled — Services Enumerated",
        category: "API Security",
        severity: "high",
        endpoint: reflectUrl,
        description: `gRPC server reflection is enabled and responded with ${serviceNames.length} service name(s). Reflection allows attackers to enumerate the complete API surface — all services, methods, and message schemas — without any prior knowledge.`,
        evidence: [
          `POST ${reflectUrl}`,
          `HTTP ${reflectR.status}`,
          ``,
          `Services discovered via reflection:`,
          ...serviceNames.map(s => `  • ${s}`),
          ``,
          `Total: ${serviceNames.length} service(s) enumerated`,
          ``,
          `An attacker can use grpcurl or evans to call any method:`,
          `  grpcurl -plaintext ${hostname}:50051 list`,
          `  grpcurl -plaintext ${hostname}:50051 ${serviceNames[0] ?? "<service>"} describe`,
        ].join("\n"),
        recommended_fix: "Disable gRPC server reflection in production. In Go: remove grpc_reflection.Register(). In Node: do not register @grpc/reflection. In Python: do not add reflection.enable_server_reflection().",
        cvss_score: 7.5,
        cwe_id: "CWE-200",
        scanner_name: "Bug-Finder/gRPC",
        scanner_family: "api",
        confidence: 0.95,
      });
      emit({ type: "log", message: `  [gRPC REFLECTION] ${serviceNames.length} services: ${serviceNames.slice(0, 3).join(", ")}` });
    }

    // ── 3. Unauthenticated method invocation ─────────────────────────────
    // For each discovered service, attempt to call it with an empty message.
    // A 200 with grpc-status=0 means the method executed without auth.
    for (const service of serviceNames.slice(0, profile === "quick" ? 2 : 6)) {
      // Try to get method list from file descriptor
      const fileProto = buildFileBySymbolProto(service);
      const fileFrame = grpcWebFrame(fileProto);
      const fileR = await ctxFetch(ctx, reflectUrl, {
        method: "POST",
        headers: { "Content-Type": "application/grpc-web+proto", "X-Grpc-Web": "1" },
        body: fileFrame as unknown as BodyInit,
      });

      const fileBuf = fileR ? await fileR.arrayBuffer().catch(() => null) : null;
      const filePayload = fileBuf ? grpcWebDecode(new Uint8Array(fileBuf)) : null;
      const methodNames = filePayload ? extractStrings(filePayload).filter(m => !m.includes(".proto") && m.length > 2 && m.length < 50) : [];

      const methodsToTest = methodNames.length > 0 ? methodNames.slice(0, 3) : ["Check", "List", "Get", "Echo"];

      for (const method of methodsToTest) {
        const methodUrl = `${grpcBase}/${service}/${method}`;
        const callR = await ctxFetch(ctx, methodUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/grpc-web+proto",
            "X-Grpc-Web": "1",
            "Accept": "application/grpc-web+proto",
          },
          body: grpcWebFrame(new Uint8Array([0])) as unknown as BodyInit, // empty message
        });

        if (!callR) continue;
        const callGrpcStatus = callR.headers.get("grpc-status") ?? "";
        const callCt = callR.headers.get("content-type") ?? "";
        const callBody = await callR.text().catch(() => "");

        // grpc-status=0 = success, grpc-status=12 = unimplemented, 16 = unauthenticated
        const isSuccess = callGrpcStatus === "0" || (callR.status === 200 && callCt.includes("grpc") && !callGrpcStatus.includes("16"));
        const isUnauthenticated = callGrpcStatus === "16";

        if (isSuccess && !isUnauthenticated) {
          findings.push({
            title: `gRPC Method Invoked Without Authentication: ${service}/${method}`,
            category: "Broken Access Control",
            severity: "critical",
            endpoint: methodUrl,
            description: `The gRPC method ${service}/${method} was successfully called with an empty message and no authentication credentials. grpc-status: ${callGrpcStatus || "0"} (success). This method is publicly accessible and may expose sensitive data or functionality.`,
            evidence: [
              `POST ${methodUrl}`,
              `Content-Type: application/grpc-web+proto`,
              `Body: [empty message — 0x00]`,
              ``,
              `Response:`,
              `  HTTP: ${callR.status}`,
              `  grpc-status: ${callGrpcStatus || "0 (success)"}`,
              `  content-type: ${callCt}`,
              `  Body preview: ${callBody.slice(0, 200)}`,
              ``,
              `Service enumerated via server reflection.`,
              `Reproduce: grpcurl -plaintext ${hostname}:50051 ${service}/${method}`,
            ].join("\n"),
            recommended_fix: "Require authentication (mTLS or token-based) for all gRPC methods. Implement interceptors that validate credentials before allowing any RPC call.",
            cvss_score: 9.1,
            cwe_id: "CWE-306",
            scanner_name: "Bug-Finder/gRPC",
            scanner_family: "api",
            confidence: 0.92,
          });
          emit({ type: "log", message: `  [gRPC AUTH BYPASS] ${service}/${method} called without auth — grpc-status=${callGrpcStatus || "0"}` });

          // ── 4. Injection testing on accessible methods ──────────────────
          // Probe string fields with SQLi/XSS/traversal payloads — build a
          // minimal proto with field 1 = the payload as a length-delimited string
          if (profile !== "quick") {
            for (const injection of GRPC_INJECTION_PAYLOADS.slice(0, 2)) {
              const payloadBytes = new TextEncoder().encode(injection.value);
              const protoMsg = new Uint8Array([0x0a, payloadBytes.length, ...payloadBytes]);
              const injR = await ctxFetch(ctx, methodUrl, {
                method: "POST",
                headers: { "Content-Type": "application/grpc-web+proto", "X-Grpc-Web": "1" },
                body: grpcWebFrame(protoMsg) as unknown as BodyInit,
              });
              if (!injR) continue;

              const injBody = await injR.text().catch(() => "");
              const injGrpcStatus = injR.headers.get("grpc-status") ?? "";

              // Error on injection or payload reflected = potential injection
              const sqlErr = /sql syntax|ORA-|pg_query|sqlite|mysql_/i.test(injBody);
              const reflected = injBody.includes(injection.value);
              const serverErr = injGrpcStatus === "13" || injR.status >= 500;

              if (sqlErr || reflected || serverErr) {
                findings.push({
                  title: `gRPC Method Injection: ${injection.name} in ${service}/${method}`,
                  category: "Injection",
                  severity: "high",
                  endpoint: methodUrl,
                  description: `The gRPC method ${service}/${method} appears vulnerable to ${injection.name}. The payload "${injection.value}" produced a suspicious response (${sqlErr ? "SQL error detected" : reflected ? "payload reflected" : `grpc-status=${injGrpcStatus}`}).`,
                  evidence: [
                    `Injection payload: ${injection.value}`,
                    `POST ${methodUrl} with proto field 1 = payload`,
                    `grpc-status: ${injGrpcStatus}`,
                    `HTTP: ${injR.status}`,
                    sqlErr ? `SQL error in response: YES` : "",
                    reflected ? `Payload reflected in response: YES` : "",
                    serverErr ? `Server error triggered: grpc-status=${injGrpcStatus}` : "",
                    `Response: ${injBody.slice(0, 300)}`,
                  ].filter(Boolean).join("\n"),
                  recommended_fix: "Validate and sanitize all gRPC message fields. Use parameterized queries for database operations. Apply server-side input validation via protobuf validators.",
                  cvss_score: 7.5,
                  cwe_id: sqlErr ? "CWE-89" : "CWE-79",
                  scanner_name: "Bug-Finder/gRPC",
                  scanner_family: "api",
                  confidence: sqlErr ? 0.85 : 0.70,
                });
                emit({ type: "log", message: `  [gRPC INJECTION] ${injection.name} in ${service}/${method}` });
              }
            }
          }
        } else if (isUnauthenticated) {
          emit({ type: "log", message: `  gRPC ${service}/${method}: grpc-status=16 (auth required — protected)` });
        }
      }
    }
  }

  // ── 5. Alt-Svc / HTTP/2 detection ────────────────────────────────────────
  const h2Res = await ctxFetch(ctx, targetUrl, { redirect: "follow" });
  if (h2Res) {
    const alt = h2Res.headers.get("alt-svc") ?? "";
    if (alt.includes("h2") || alt.includes("h3")) {
      emit({ type: "log", message: `HTTP/2 support detected via Alt-Svc: ${alt}` });
      findings.push({
        title: "HTTP/2 Support Detected — gRPC Attack Surface",
        category: "API Security",
        severity: "info",
        endpoint: targetUrl,
        description: `The server supports HTTP/2 (Alt-Svc: ${alt}). HTTP/2 is required for gRPC. If gRPC services are running, ensure they require authentication and disable server reflection.`,
        evidence: `Alt-Svc: ${alt}`,
        recommended_fix: "Audit all HTTP/2 endpoints for gRPC services. Disable gRPC server reflection in production.",
        cvss_score: 0,
        cwe_id: "CWE-284",
        scanner_name: "Bug-Finder/gRPC",
        scanner_family: "api",
        confidence: 0.75,
      });
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No gRPC services detected" });
  }

  emit({ type: "engine_done", engine: "Bug-Finder/gRPC", message: `gRPC check complete — ${findings.length} finding(s)` });
  return findings;
}
