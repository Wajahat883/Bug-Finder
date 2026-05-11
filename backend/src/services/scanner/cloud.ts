import { ScanContext, ScanFinding, safeFetch } from "./types";

export async function runCloudCheck(ctx: ScanContext): Promise<ScanFinding[]> {
  const { targetUrl, emit, profile } = ctx;
  const findings: ScanFinding[] = [];

  emit({ type: "engine_start", engine: "Cloud/Container Scanner", message: "Checking cloud storage, Docker, and Kubernetes exposure" });

  const base = new URL(targetUrl).origin;
  const hostname = new URL(targetUrl).hostname;

  // 1. S3 / Cloud Storage Bucket Detection
  emit({ type: "log", message: "Checking for exposed cloud storage buckets..." });

  const domainParts = hostname.replace(/\./g, "-");
  const baseDomain = hostname.split(".").slice(-2, -1)[0] ?? hostname.split(".")[0];

  const bucketNames = [
    baseDomain, domainParts, `${baseDomain}-backup`, `${baseDomain}-assets`,
    `${baseDomain}-uploads`, `${baseDomain}-static`, `${baseDomain}-media`,
    `${baseDomain}-files`, `${baseDomain}-data`,
  ];

  const s3Endpoints = [
    ...bucketNames.slice(0, profile === "quick" ? 3 : profile === "standard" ? 5 : 9).map(b => `https://${b}.s3.amazonaws.com`),
    ...bucketNames.slice(0, 3).map(b => `https://storage.googleapis.com/${b}`),
    ...bucketNames.slice(0, 2).map(b => `https://${b}.blob.core.windows.net`),
  ];

  for (const bucketUrl of s3Endpoints) {
    const r = await safeFetch(bucketUrl, { redirect: "follow" });
    if (!r) continue;

    const body = await r.text().catch(() => "");
    const ct = r.headers.get("content-type") ?? "";

    if (r.status === 200 && (body.includes("<ListBucketResult") || body.includes("<Contents>") || body.includes('"kind": "storage'))) {
      findings.push({
        title: "Public Cloud Storage Bucket Found",
        category: "Cloud Security",
        severity: "critical",
        endpoint: bucketUrl,
        description: `A publicly accessible cloud storage bucket was found at ${bucketUrl}. The bucket listing is enabled, revealing all stored files. This can expose sensitive data including backups, configuration files, and user uploads.`,
        evidence: `GET ${bucketUrl}\nHTTP ${r.status}\nBucket listing enabled\nContent preview: ${body.slice(0, 400)}`,
        recommended_fix: "Disable public bucket access. Enable bucket ACLs. Review all stored files for sensitive content. Enable bucket logging and versioning. Use signed URLs for temporary access.",
        cvss_score: 9.8,
        cwe_id: "CWE-284",
        scanner_name: "Cloud Scanner",
        scanner_family: "cloud",
        confidence: 0.95,
      });
      emit({ type: "log", message: `  [CRITICAL] Public S3 bucket: ${bucketUrl}` });
    } else if (r.status === 403 && body.includes("AccessDenied")) {
      findings.push({
        title: "Cloud Storage Bucket Exists (Access Denied)",
        category: "Cloud Security",
        severity: "low",
        endpoint: bucketUrl,
        description: `A cloud storage bucket named after the target domain exists at ${bucketUrl} but access is restricted. While not currently readable, the bucket's existence confirms infrastructure details. Monitor for ACL misconfigurations.`,
        evidence: `GET ${bucketUrl}\nHTTP ${r.status}\nBucket exists but access is denied`,
        recommended_fix: "Confirm the bucket access policy is correct. Enable bucket-level MFA delete. Monitor for accidental permission changes.",
        cvss_score: 3.1,
        cwe_id: "CWE-284",
        scanner_name: "Cloud Scanner",
        scanner_family: "cloud",
        confidence: 0.85,
      });
      emit({ type: "log", message: `  Bucket exists (locked): ${bucketUrl}` });
    }
  }

  // 2. Docker / Container Exposure
  emit({ type: "log", message: "Checking for Docker/container exposure..." });

  const dockerPaths = [
    { path: "/.dockerenv", title: "Docker Environment File Exposed", severity: "medium" as const, cvss: 5.3 },
    { path: "/v2/", title: "Docker Registry API Exposed", severity: "high" as const, cvss: 7.5 },
    { path: "/v2/_catalog", title: "Docker Registry Catalog Exposed", severity: "critical" as const, cvss: 9.1 },
    { path: "/.docker/config.json", title: "Docker Config Credentials Exposed", severity: "critical" as const, cvss: 9.8 },
  ];

  for (const check of dockerPaths) {
    const url = `${base}${check.path}`;
    const r = await safeFetch(url, { redirect: "follow" });
    if (!r) continue;

    const body = await r.text().catch(() => "");
    if (r.status === 200 && body.length > 0) {
      findings.push({
        title: check.title,
        category: "Cloud Security",
        severity: check.severity,
        endpoint: url,
        description: `${check.title} at ${url}. This exposes container infrastructure details that can aid attackers in further exploitation.`,
        evidence: `GET ${url}\nHTTP ${r.status}\nContent: ${body.slice(0, 300)}`,
        recommended_fix: "Block web access to Docker-related files. Never expose Docker registry or management APIs to the internet. Use Docker secrets for credential management.",
        cvss_score: check.cvss,
        cwe_id: "CWE-284",
        scanner_name: "Cloud Scanner",
        scanner_family: "cloud",
        confidence: 0.9,
      });
      emit({ type: "log", message: `  ${check.title} at ${url}` });
    }
  }

  // 3. Kubernetes Exposure
  emit({ type: "log", message: "Checking for Kubernetes API exposure..." });

  const k8sPaths = [
    { path: "/api/v1/pods", title: "Kubernetes API — Pod List Exposed", severity: "critical" as const, cvss: 9.8 },
    { path: "/api/v1/namespaces", title: "Kubernetes API — Namespace List Exposed", severity: "critical" as const, cvss: 9.8 },
    { path: "/metrics", title: "Prometheus/Kubernetes Metrics Exposed", severity: "medium" as const, cvss: 5.3 },
    { path: "/actuator", title: "Spring Boot Actuator Exposed", severity: "high" as const, cvss: 7.5 },
    { path: "/actuator/env", title: "Spring Boot Actuator /env Exposed", severity: "critical" as const, cvss: 9.8 },
    { path: "/actuator/heapdump", title: "Spring Boot Heap Dump Accessible", severity: "critical" as const, cvss: 9.8 },
    { path: "/actuator/beans", title: "Spring Boot Beans Config Exposed", severity: "high" as const, cvss: 7.5 },
    { path: "/.env.local", title: "Environment File .env.local Exposed", severity: "critical" as const, cvss: 9.8 },
    { path: "/.env.production", title: "Production Environment File Exposed", severity: "critical" as const, cvss: 9.8 },
  ];

  for (const check of k8sPaths) {
    const url = `${base}${check.path}`;
    const r = await safeFetch(url, { redirect: "follow" });
    if (!r) continue;

    const body = await r.text().catch(() => "");
    if (r.status === 200 && body.length > 50) {
      const isK8s = body.includes("apiVersion") || body.includes("kind") || body.includes("metadata");
      const isMetrics = body.includes("# HELP") || body.includes("# TYPE");
      const isActuator = body.includes("_links") || body.includes("contexts") || body.includes("beans");
      const isEnvFile = body.includes("=") && (body.includes("PASSWORD") || body.includes("SECRET") || body.includes("KEY") || body.includes("TOKEN"));

      if (isK8s || isMetrics || isActuator || isEnvFile || body.length > 200) {
        findings.push({
          title: check.title,
          category: "Cloud Security",
          severity: check.severity,
          endpoint: url,
          description: `${check.title} is accessible without authentication. This can expose sensitive infrastructure data, secrets, and allow attackers to manipulate the cluster.`,
          evidence: `GET ${url}\nHTTP ${r.status}\nContent-Type: ${r.headers.get("content-type")}\nResponse (${body.length} bytes): ${body.slice(0, 400)}`,
          recommended_fix: "Restrict access to management APIs and configuration endpoints. Use network policies to prevent external access. Enable Kubernetes RBAC. Remove actuator endpoints in production.",
          cvss_score: check.cvss,
          cwe_id: "CWE-284",
          scanner_name: "Cloud Scanner",
          scanner_family: "cloud",
          confidence: 0.9,
        });
        emit({ type: "log", message: `  [${check.severity.toUpperCase()}] ${check.title}` });
      }
    }
  }

  if (findings.length === 0) {
    emit({ type: "log", message: "No cloud storage or container exposure found" });
  }

  emit({ type: "engine_done", engine: "Cloud/Container Scanner", message: `Cloud check complete — ${findings.length} finding(s)` });
  return findings;
}
