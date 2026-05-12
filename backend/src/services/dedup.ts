import { ObjectId } from "mongodb";
import { col } from "../lib/db";

// Levenshtein distance
function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) => Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)));
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) dp[i]![j] = dp[i - 1]![j - 1]!;
      else dp[i]![j] = 1 + Math.min(dp[i - 1]![j]!, dp[i]![j - 1]!, dp[i - 1]![j - 1]!);
    }
  }
  return dp[m]![n]!;
}

export function similarity(a: string, b: string): number {
  if (a === b) return 1;
  const maxLen = Math.max(a.length, b.length);
  if (maxLen === 0) return 1;
  return 1 - levenshtein(a.toLowerCase(), b.toLowerCase()) / maxLen;
}

export async function isDuplicate(
  scanJobId: string,
  title: string,
  endpoint: string,
  category: string
): Promise<{ isDup: boolean; existingId?: string; similarity?: number }> {
  if (!ObjectId.isValid(scanJobId)) return { isDup: false };
  const existing = (await col("findings").find({
    scan_job_id: new ObjectId(scanJobId),
    category,
    endpoint,
    is_duplicate: { $ne: true },
  } as Record<string, unknown>).toArray()) as Array<Record<string, unknown>>;

  for (const f of existing) {
    const sim = similarity(title, String(f["title"] ?? ""));
    if (sim >= 0.85) {
      return { isDup: true, existingId: String(f["_id"]), similarity: sim };
    }
  }
  return { isDup: false };
}

export async function clusterFindings(scanJobId: string): Promise<Array<{
  representative: string;
  cluster: string[];
  title: string;
  count: number;
}>> {
  if (!ObjectId.isValid(scanJobId)) return [];
  const findings = (await col("findings").find({ scan_job_id: new ObjectId(scanJobId) } as Record<string, unknown>).toArray()) as Array<Record<string, unknown>>;

  const visited = new Set<string>();
  const clusters: Array<{ representative: string; cluster: string[]; title: string; count: number }> = [];

  for (const f of findings) {
    const fId = String(f["_id"]);
    if (visited.has(fId)) continue;
    visited.add(fId);

    const cluster: string[] = [fId];
    for (const other of findings) {
      const otherId = String(other["_id"]);
      if (visited.has(otherId)) continue;
      if (
        String(f["category"]) === String(other["category"]) &&
        String(f["endpoint"]) === String(other["endpoint"]) &&
        similarity(String(f["title"] ?? ""), String(other["title"] ?? "")) >= 0.85
      ) {
        cluster.push(otherId);
        visited.add(otherId);
      }
    }

    clusters.push({ representative: fId, cluster, title: String(f["title"] ?? ""), count: cluster.length });
  }

  return clusters;
}
