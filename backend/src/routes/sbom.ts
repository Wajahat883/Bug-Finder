/**
 * SBOM (Software Bill of Materials) routes
 *
 * GET /sbom/:scanId          — CycloneDX 1.4 JSON
 * GET /sbom/:scanId/download — CycloneDX 1.4 JSON download attachment
 * GET /sbom/:scanId/spdx     — SPDX 2.3 JSON
 */

import { Router } from "express";
import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/rbac";
import crypto from "crypto";

const router = Router();

// ── Shared: load findings for a scan ─────────────────────────────────────────

async function getScanFindings(scanId: string): Promise<Array<Record<string, unknown>> | null> {
  if (!ObjectId.isValid(scanId)) return null;

  const scan = await col("scan_jobs").findOne(
    { _id: new ObjectId(scanId) } as Record<string, unknown>
  ) as Record<string, unknown> | null;

  if (!scan) return null;

  const findings = await col("findings")
    .find({ scan_job_id: new ObjectId(scanId) } as Record<string, unknown>)
    .toArray() as Array<Record<string, unknown>>;

  return findings;
}

// ── CycloneDX 1.4 builder ────────────────────────────────────────────────────

function buildCycloneDX(scanId: string, findings: Array<Record<string, unknown>>): Record<string, unknown> {
  const now = new Date().toISOString();

  // Each unique endpoint domain → component
  const domainSet = new Set<string>();
  for (const f of findings) {
    const ep = String(f["endpoint"] ?? "");
    try {
      const hostname = new URL(ep.startsWith("http") ? ep : `https://${ep}`).hostname;
      if (hostname) domainSet.add(hostname);
    } catch { /* ignore */ }
  }

  const components = [...domainSet].map((domain, idx) => ({
    type: "application",
    "bom-ref": `component-${idx + 1}`,
    name: domain,
    version: "unknown",
    purl: `pkg:generic/${domain}@unknown`,
    properties: [
      { name: "scan:id", value: scanId },
      { name: "scan:domain", value: domain },
    ],
  }));

  // Each finding with a cve_id → vulnerability entry
  const vulnerabilities = findings
    .filter((f) => f["cve_id"])
    .map((f, idx) => {
      const cveId = String(f["cve_id"]);
      const severityMap: Record<string, string> = {
        critical: "critical",
        high: "high",
        medium: "medium",
        low: "low",
        info: "info",
        informational: "info",
      };
      const sev = String(f["severity"] ?? "medium").toLowerCase();

      return {
        "bom-ref": `vuln-${idx + 1}`,
        id: cveId,
        source: {
          name: "NVD",
          url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
        },
        ratings: [
          {
            source: { name: "Bug Finder Pro" },
            score: typeof f["cvss_v3_score"] === "number" ? f["cvss_v3_score"]
              : typeof f["cvss_score"] === "number" ? f["cvss_score"] : null,
            severity: severityMap[sev] ?? "medium",
            method: "CVSSv3",
          },
        ],
        cwes: f["cwe_id"]
          ? [parseInt(String(f["cwe_id"]).replace(/\D/g, ""), 10)].filter((n) => !isNaN(n))
          : [],
        description: String(f["nvd_description"] ?? f["description"] ?? ""),
        detail: String(f["evidence"] ?? "").slice(0, 500),
        recommendation: String(f["recommended_fix"] ?? ""),
        properties: [
          { name: "bugfinder:findingId", value: String(f["_id"]) },
          { name: "bugfinder:endpoint", value: String(f["endpoint"] ?? "") },
          { name: "bugfinder:scanner", value: String(f["scanner_name"] ?? "") },
          ...(typeof f["epss_score"] === "number"
            ? [{ name: "epss:score", value: String(f["epss_score"]) }]
            : []),
          ...(typeof f["epss_percentile"] === "number"
            ? [{ name: "epss:percentile", value: String(f["epss_percentile"]) }]
            : []),
        ],
        affects: [
          {
            ref: `pkg:generic/${(() => {
              try { return new URL(String(f["endpoint"] ?? "")).hostname; } catch { return "unknown"; }
            })()}@unknown`,
          },
        ],
      };
    });

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.4",
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: now,
      tools: [{ vendor: "Bug Finder Pro", name: "Bug Finder Pro Scanner", version: "1.0.0" }],
      component: {
        type: "application",
        name: `Scan ${scanId}`,
        version: "1.0.0",
      },
    },
    components,
    vulnerabilities,
  };
}

// ── SPDX 2.3 builder ─────────────────────────────────────────────────────────

function buildSpdx(scanId: string, findings: Array<Record<string, unknown>>): Record<string, unknown> {
  const now = new Date().toISOString();

  // Unique domains → SPDX packages
  const domainSet = new Set<string>();
  for (const f of findings) {
    const ep = String(f["endpoint"] ?? "");
    try {
      const hostname = new URL(ep.startsWith("http") ? ep : `https://${ep}`).hostname;
      if (hostname) domainSet.add(hostname);
    } catch { /* ignore */ }
  }

  const packages = [...domainSet].map((domain, idx) => ({
    SPDXID: `SPDXRef-Package-${idx + 1}`,
    name: domain,
    versionInfo: "NOASSERTION",
    downloadLocation: `https://${domain}`,
    filesAnalyzed: false,
    homepage: `https://${domain}`,
    packageVerificationCode: { packageVerificationCodeValue: "NOASSERTION" },
    licenseConcluded: "NOASSERTION",
    licenseDeclared: "NOASSERTION",
    copyrightText: "NOASSERTION",
    annotations: [
      {
        annotationType: "REVIEW",
        annotator: "Tool: Bug Finder Pro",
        annotationDate: now,
        comment: `Discovered during scan ${scanId}`,
      },
    ],
  }));

  // CVE findings → SPDX snippets (there is no native vuln section in SPDX 2.3,
  // so we represent them as external document references + annotations)
  const cveFindings = findings.filter((f) => f["cve_id"]);

  const relationships = [...domainSet].map((_domain, idx) => ({
    spdxElementId: "SPDXRef-DOCUMENT",
    relationshipType: "DESCRIBES",
    relatedSpdxElement: `SPDXRef-Package-${idx + 1}`,
  }));

  const hasExtractedLicensingInfos = cveFindings.map((f, idx) => ({
    licenseId: `LicenseRef-CVE-${idx + 1}`,
    name: String(f["cve_id"]),
    comment: String(f["nvd_description"] ?? f["description"] ?? "").slice(0, 300),
    extractedText: `CVE: ${f["cve_id"]} | Severity: ${f["severity"]} | CVSS: ${f["cvss_v3_score"] ?? f["cvss_score"] ?? "N/A"} | EPSS: ${f["epss_score"] ?? "N/A"}`,
  }));

  return {
    SPDXID: "SPDXRef-DOCUMENT",
    spdxVersion: "SPDX-2.3",
    creationInfo: {
      created: now,
      creators: ["Tool: Bug Finder Pro", "Organization: Bug Finder Pro"],
      comment: `Generated from scan ${scanId}`,
    },
    name: `SBOM-scan-${scanId}`,
    dataLicense: "CC0-1.0",
    documentNamespace: `https://bugfinderpro.com/sbom/${scanId}-${Date.now()}`,
    documentDescribes: packages.map((p) => p.SPDXID),
    packages,
    relationships,
    hasExtractedLicensingInfos,
    annotations: cveFindings.map((f, idx) => ({
      spdxElementId: "SPDXRef-DOCUMENT",
      annotationType: "REVIEW",
      annotator: "Tool: Bug Finder Pro",
      annotationDate: now,
      comment: `CVE-${idx + 1}: ${f["cve_id"]} at ${f["endpoint"]} — ${f["severity"]} severity`,
    })),
  };
}

// ── GET /sbom/:scanId ─────────────────────────────────────────────────────────

router.get("/sbom/:scanId", requireAuth, async (req, res) => {
  try {
    const scanId = String(req.params["scanId"]);
    const findings = await getScanFindings(scanId);
    if (findings === null) return res.status(404).json({ error: "Scan not found" });

    const sbom = buildCycloneDX(scanId, findings);
    res.json(sbom);
  } catch (err) {
    logger.error({ err }, "SBOM generation error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── GET /sbom/:scanId/download ────────────────────────────────────────────────

router.get("/sbom/:scanId/download", requireAuth, async (req, res) => {
  try {
    const scanId = String(req.params["scanId"]);
    const findings = await getScanFindings(scanId);
    if (findings === null) return res.status(404).json({ error: "Scan not found" });

    const sbom = buildCycloneDX(scanId, findings);

    res.setHeader("Content-Type", "application/json");
    res.setHeader("Content-Disposition", `attachment; filename="sbom-${scanId}.json"`);
    res.json(sbom);
  } catch (err) {
    logger.error({ err }, "SBOM download error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── GET /sbom/:scanId/spdx ────────────────────────────────────────────────────

router.get("/sbom/:scanId/spdx", requireAuth, async (req, res) => {
  try {
    const scanId = String(req.params["scanId"]);
    const findings = await getScanFindings(scanId);
    if (findings === null) return res.status(404).json({ error: "Scan not found" });

    const spdx = buildSpdx(scanId, findings);

    res.setHeader("Content-Type", "application/json");
    res.setHeader("Content-Disposition", `attachment; filename="sbom-${scanId}.spdx.json"`);
    res.json(spdx);
  } catch (err) {
    logger.error({ err }, "SPDX generation error");
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
