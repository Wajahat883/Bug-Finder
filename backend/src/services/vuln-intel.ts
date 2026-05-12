import { ObjectId } from "mongodb";
import { col } from "../lib/db";
import { logger } from "../lib/logger";

// Cache for CISA KEV list (24h TTL)
let kevCache: { data: Set<string>; fetchedAt: Date } | null = null;

export async function getEpssScore(cveId: string): Promise<{ epss: number; percentile: number } | null> {
  try {
    const url = `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveId)}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(8000) });
    if (!res.ok) return null;
    const data = await res.json() as Record<string, unknown>;
    const items = (data["data"] as Array<Record<string, unknown>>) ?? [];
    if (items.length === 0) return null;
    const item = items[0]!;
    return {
      epss: parseFloat(String(item["epss"] ?? "0")),
      percentile: parseFloat(String(item["percentile"] ?? "0")),
    };
  } catch {
    return null;
  }
}

export async function checkCisaKev(cveId: string): Promise<boolean> {
  try {
    const now = new Date();
    // Refresh cache if older than 24h
    if (!kevCache || (now.getTime() - kevCache.fetchedAt.getTime()) > 24 * 60 * 60 * 1000) {
      const res = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", {
        signal: AbortSignal.timeout(15000),
      });
      if (res.ok) {
        const data = await res.json() as Record<string, unknown>;
        const vulns = (data["vulnerabilities"] as Array<Record<string, unknown>>) ?? [];
        kevCache = {
          data: new Set(vulns.map((v) => String(v["cveID"] ?? ""))),
          fetchedAt: now,
        };
      }
    }
    return kevCache?.data.has(cveId) ?? false;
  } catch {
    return false;
  }
}

export async function enrichFindingWithIntel(findingId: string): Promise<void> {
  try {
    if (!ObjectId.isValid(findingId)) return;
    const finding = (await col("findings").findOne({ _id: new ObjectId(findingId) } as Record<string, unknown>)) as Record<string, unknown> | null;
    if (!finding) return;

    // Extract CVE IDs from cve_enrichment or evidence
    const cveIds: string[] = [];
    const cveEnrichment = finding["cve_enrichment"] as Array<Record<string, unknown>> | undefined;
    if (Array.isArray(cveEnrichment)) {
      for (const c of cveEnrichment) {
        const cveId = String(c["id"] ?? "");
        if (cveId.startsWith("CVE-")) cveIds.push(cveId);
      }
    }
    // Also try evidence text
    const evidence = String(finding["evidence"] ?? "");
    const cveMatches = evidence.match(/CVE-\d{4}-\d{4,}/g) ?? [];
    for (const c of cveMatches) {
      if (!cveIds.includes(c)) cveIds.push(c);
    }

    if (cveIds.length === 0) return;

    const primaryCve = cveIds[0]!;
    const [epssResult, isKev] = await Promise.all([
      getEpssScore(primaryCve),
      checkCisaKev(primaryCve),
    ]);

    const update: Record<string, unknown> = { intel_enriched_at: new Date(), is_cisa_kev: isKev };
    if (epssResult) {
      update["epss_score"] = epssResult.epss;
      update["epss_percentile"] = epssResult.percentile;
    }

    await col("findings").updateOne(
      { _id: new ObjectId(findingId) } as Record<string, unknown>,
      { $set: update }
    );

    logger.info({ findingId, primaryCve, epssResult, isKev }, "Finding enriched with intel");
  } catch (err) {
    logger.error({ err, findingId }, "Finding intel enrichment error");
  }
}
