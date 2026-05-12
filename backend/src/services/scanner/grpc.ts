import { ScanContext, ScanFinding, ctxFetch } from "./types";

const GRPC_PORTS = [50051, 50052, 9090, 9091, 8090];
const GRPC_WEB_PATHS = ["/grpc", "/grpc-web", "/api/grpc"];

export async function runGrpcCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, profile } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "gRPC Scanner", message: "Detecting gRPC endpoints and reflection services" });

  const base = new URL(targetUrl).origin;
  const hostname = new URL(targetUrl).hostname;

  if (hostname === "localhost" || hostname.startsWith("127.") || hostname.endsWith(".replit.dev")) {
    emit({ type: "log", message: "Skipping gRPC port scan for local/dev host" });
    emit({ type: "engine_done", engine: "gRPC Scanner", message: "Skipped (local host)" });
    return findings;
  }

  // Check for gRPC-Web proxy endpoints
  for (const path of GRPC_WEB_PATHS) {
    const url = `${base}${path}`;
    const r = await ctxFetch(ctx, url, {
      method: "POST",
      headers: {
        "Content-Type": "application/grpc-web+proto",
        "X-Grpc-Web": "1",
        Accept: "application/grpc-web+proto",
      },
      body: new Uint8Array([0, 0, 0, 0, 0]).buffer as BodyInit,
    });

    if (!r) continue;

    const ct = r.headers.get("content-type") ?? "";
    const grpcStatus = r.headers.get("grpc-status") ?? r.headers.get("x-grpc-status") ?? "";

    if (ct.includes("grpc") || grpcStatus) {
      findings.push({
        title: "gRPC-Web Endpoint Detected",
        category: "API Security",
        severity: "info",
        endpoint: url,
        description: `A gRPC-Web endpoint was found at ${url}. gRPC services require specialized security testing. Ensure authentication, authorization, and input validation are enforced on all gRPC methods.`,
        evidence: `POST ${url}\nContent-Type: application/grpc-web+proto\nHTTP ${r.status}\ngrpc-status: ${grpcStatus}\ncontent-type: ${ct}`,
        recommended_fix: "Implement authentication for all gRPC services. Enable TLS. Disable gRPC server reflection in production. Apply input validation on all message fields.",
        cvss_score: 3.7,
        cwe_id: "CWE-284",
        scanner_name: "gRPC Scanner",
        scanner_family: "api",
        confidence: 0.85,
      });
      emit({ type: "log", message: `gRPC-Web endpoint found: ${url}` });

      // Try server reflection (should be disabled in prod)
      const reflectUrl = `${url}/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo`;
      const reflectR = await ctxFetch(ctx, reflectUrl, {
        method: "POST",
        headers: { "Content-Type": "application/grpc-web+proto", "X-Grpc-Web": "1" },
      });
      if (reflectR && reflectR.status === 200) {
        findings.push({
          title: "gRPC Server Reflection Enabled in Production",
          category: "API Security",
          severity: "medium",
          endpoint: reflectUrl,
          description: "gRPC server reflection is enabled. This allows clients to enumerate all available services, methods, and message types without prior knowledge — significantly aiding attackers.",
          evidence: `POST ${reflectUrl}\nHTTP ${reflectR.status} — reflection service accessible`,
          recommended_fix: "Disable gRPC server reflection in production: remove grpc.reflection.v1alpha.ServerReflectionServer from your gRPC server setup.",
          cvss_score: 5.3,
          cwe_id: "CWE-200",
          scanner_name: "gRPC Scanner",
          scanner_family: "api",
          confidence: 0.9,
        });
        emit({ type: "log", message: `  gRPC reflection enabled!` });
      }
    }
  }

  // Check HTTP/2 support (gRPC requires HTTP/2)
  const h2Res = await ctxFetch(ctx, targetUrl, { redirect: "follow" });
  if (h2Res) {
    // Node fetch doesn't expose HTTP version directly, but we can check headers
    const via = h2Res.headers.get("via") ?? "";
    const alt = h2Res.headers.get("alt-svc") ?? "";

    if (alt.includes("h2") || alt.includes("h3")) {
      emit({ type: "log", message: `HTTP/2 or HTTP/3 support detected via Alt-Svc: ${alt}` });
      findings.push({
        title: "HTTP/2 Support Detected — gRPC Attack Surface",
        category: "API Security",
        severity: "info",
        endpoint: targetUrl,
        description: `The server supports HTTP/2 (Alt-Svc: ${alt}). HTTP/2 is required for gRPC. If gRPC services are running, ensure they require authentication and disable server reflection.`,
        evidence: `Alt-Svc: ${alt}\nVia: ${via}`,
        recommended_fix: "Audit all HTTP/2 endpoints for gRPC services. Ensure gRPC services enforce authentication. Disable reflection.",
        cvss_score: 0,
        cwe_id: "CWE-284",
        scanner_name: "gRPC Scanner",
        scanner_family: "api",
        confidence: 0.75,
      });
    }
  }

  // Check for well-known gRPC admin paths
  const adminPaths = [
    "/grpc.health.v1.Health/Check",
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
  ];

  for (const adminPath of adminPaths) {
    const adminUrl = `${base}${adminPath}`;
    const r = await ctxFetch(ctx, adminUrl, {
      method: "POST",
      headers: { "Content-Type": "application/grpc+proto" },
    });
    if (r && r.status !== 404 && r.status !== 405) {
      const ct = r.headers.get("content-type") ?? "";
      if (ct.includes("grpc")) {
        findings.push({
          title: `gRPC Service Accessible: ${adminPath}`,
          category: "API Security",
          severity: "medium",
          endpoint: adminUrl,
          description: `The gRPC service at ${adminPath} is accessible. This may expose health check data or service enumeration capabilities.`,
          evidence: `POST ${adminUrl}\nHTTP ${r.status}\ncontent-type: ${ct}`,
          recommended_fix: "Restrict access to gRPC admin services. Require authentication for all gRPC endpoints.",
          cvss_score: 5.3,
          cwe_id: "CWE-284",
          scanner_name: "gRPC Scanner",
          scanner_family: "api",
          confidence: 0.8,
        });
      }
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No gRPC services detected" });
  }

  emit({ type: "engine_done", engine: "gRPC Scanner", message: `gRPC check complete — ${findings.length} finding(s)` });
  return findings;
}
