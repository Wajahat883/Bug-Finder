import { col } from "../../lib/db";
import { logger } from "../../lib/logger";

interface FpPattern {
  id: string;
  pattern: string;
  field: "title" | "endpoint" | "category" | "scanner_name" | "evidence";
  matchType: "exact" | "contains" | "regex";
  severity: string;
  created_at: Date;
  match_count: number;
  last_matched?: Date;
}

interface FpSuppression {
  endpoint: string;
  scannerName: string;
  findingHash: string;
  suppressedBy: string;
  suppressedAt: Date;
  reason: string;
}

const suppressionCache: Map<string, FpSuppression> = new Map();
let cacheLoaded = false;

async function loadSuppressions(): Promise<void> {
  if (cacheLoaded) return;
  try {
    const rows = await col("fp_suppressions").find({}).toArray() as Array<Record<string, unknown>>;
    for (const row of rows) {
      const key = hashFinding(String(row["endpoint"] ?? ""), String(row["scanner_name"] ?? ""));
      suppressionCache.set(key, {
        endpoint: String(row["endpoint"] ?? ""),
        scannerName: String(row["scanner_name"] ?? ""),
        findingHash: String(row["finding_hash"] ?? ""),
        suppressedBy: String(row["suppressed_by"] ?? "system"),
        suppressedAt: new Date(String(row["suppressed_at"] ?? new Date().toISOString())),
        reason: String(row["reason"] ?? ""),
      });
    }
    cacheLoaded = true;
    logger.info({ count: suppressionCache.size }, "FP suppression cache loaded");
  } catch {
    cacheLoaded = true;
  }
}

function hashFinding(endpoint: string, scannerName: string): string {
  return `${endpoint}|${scannerName}`.toLowerCase();
}

export async function isSuppressed(
  title: string,
  endpoint: string,
  scannerName: string,
  description: string
): Promise<boolean> {
  await loadSuppressions();

  const key = hashFinding(endpoint, scannerName);
  if (suppressionCache.has(key)) return true;

  try {
    const patterns = await col("fp_patterns").find({}).toArray() as Array<Record<string, unknown>>;
    for (const pat of patterns) {
      const field = String(pat["field"] ?? "title");
      const pattern = String(pat["pattern"] ?? "");
      const matchType = String(pat["match_type"] ?? "contains");
      const value = field === "title" ? title :
                    field === "endpoint" ? endpoint :
                    field === "scanner_name" ? scannerName :
                    description;

      let matched = false;
      if (matchType === "exact") matched = value.toLowerCase() === pattern.toLowerCase();
      else if (matchType === "contains") matched = value.toLowerCase().includes(pattern.toLowerCase());
      else if (matchType === "regex") {
        try { matched = new RegExp(pattern, "i").test(value); } catch { continue; }
      }

      if (matched) {
        await col("fp_patterns").updateOne(
          { _id: pat["_id"] } as Record<string, unknown>,
          { $inc: { match_count: 1 }, $set: { last_matched: new Date() } }
        );
        return true;
      }
    }
  } catch (err) {
    logger.warn({ err }, "FP check error — bypassing suppression");
  }

  return false;
}

export async function suppressFinding(
  finding: {
    title: string;
    endpoint: string;
    scannerName: string;
    description: string;
    suppressedBy?: string;
    reason?: string;
  },
  options?: { createPattern?: boolean; globalSuppress?: boolean }
): Promise<void> {
  await loadSuppressions();

  const key = hashFinding(finding.endpoint, finding.scannerName);
  const suppression: FpSuppression = {
    endpoint: finding.endpoint,
    scannerName: finding.scannerName,
    findingHash: key,
    suppressedBy: finding.suppressedBy ?? "user",
    suppressedAt: new Date(),
    reason: finding.reason ?? "Marked as false positive",
  };

  suppressionCache.set(key, suppression);

  try {
    await col("fp_suppressions").insertOne({
      ...suppression,
      _created: new Date(),
    });
  } catch { /* duplicate — already suppressed */ }

  if (options?.createPattern || options?.globalSuppress) {
    try {
      const existing = await col("fp_patterns").findOne({
        pattern: finding.title,
        field: "title",
      } as Record<string, unknown>);

      if (!existing) {
        await col("fp_patterns").insertOne({
          pattern: finding.title,
          field: "title",
          match_type: "contains",
          severity: "any",
          created_at: new Date(),
          match_count: 1,
        });
        logger.info({ title: finding.title }, "FP pattern created");
      }
    } catch (err) {
      logger.warn({ err }, "Failed to create FP pattern");
    }
  }

  logger.info({ endpoint: finding.endpoint, scanner: finding.scannerName }, "Finding suppressed");
}

export async function clearSuppression(endpoint: string, scannerName: string): Promise<void> {
  const key = hashFinding(endpoint, scannerName);
  suppressionCache.delete(key);
  try {
    await col("fp_suppressions").deleteMany({
      endpoint,
      scanner_name: scannerName,
    } as Record<string, unknown>);
  } catch { /* ignore */ }
}

export function getSuppressionStats() {
  return {
    totalSuppressed: suppressionCache.size,
    endpoints: [...new Set([...suppressionCache.values()].map(s => s.endpoint))].length,
  };
}
