/**
 * Correlation & Deduplication Engine
 *
 * Merges duplicate findings across multiple scanner modules by normalizing
 * title similarity and endpoint matching. Produces a canonical dedup key
 * that survives minor variations in wording or URL formatting.
 *
 * Features:
 *   - Levenshtein-based title similarity (configurable threshold)
 *   - Endpoint normalization (strip query, lowercase origin + pathname)
 *   - Category-aware merging (same category only)
 *   - Batch deduplication for post-scan cleanup
 */

import { normalizeEndpoint } from "./normalize-engine";

export function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;

  let prev = new Array(n + 1);
  let curr = new Array(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
    }
    const tmp = prev;
    prev = curr;
    curr = tmp;
  }
  return prev[n];
}

export function titleSimilarity(a: string, b: string): number {
  const maxLen = Math.max(a.length, b.length);
  if (maxLen === 0) return 1.0;
  return 1.0 - levenshteinDistance(a.toLowerCase(), b.toLowerCase()) / maxLen;
}

export interface CorrelationKey {
  title: string;
  category: string;
  endpoint: string;
}

export function buildCorrelationKey(finding: {
  title: string;
  category: string;
  endpoint: string;
}): CorrelationKey {
  return {
    title: finding.title.toLowerCase().replace(/\s+/g, " ").trim(),
    category: finding.category.toLowerCase(),
    endpoint: normalizeEndpoint(finding.endpoint),
  };
}

export function areCorrelated(
  a: CorrelationKey,
  b: CorrelationKey,
  similarityThreshold = 0.85
): boolean {
  if (a.category !== b.category) return false;
  if (a.endpoint !== b.endpoint) return false;
  return titleSimilarity(a.title, b.title) >= similarityThreshold;
}

export interface DedupBatchResult {
  kept: number;
  suppressed: number;
  clusters: Array<{
    representative: CorrelationKey;
    members: CorrelationKey[];
    similarity: number;
  }>;
}

export function deduplicateBatch(
  findings: CorrelationKey[],
  similarityThreshold = 0.85
): DedupBatchResult {
  const clusters: Array<{
    representative: CorrelationKey;
    members: CorrelationKey[];
    similarity: number;
  }> = [];
  const suppressed = new Set<number>();

  for (let i = 0; i < findings.length; i++) {
    if (suppressed.has(i)) continue;
    const cluster = { representative: findings[i], members: [findings[i]], similarity: 1.0 };
    for (let j = i + 1; j < findings.length; j++) {
      if (suppressed.has(j)) continue;
      if (areCorrelated(findings[i], findings[j], similarityThreshold)) {
        cluster.members.push(findings[j]);
        suppressed.add(j);
      }
    }
    clusters.push(cluster);
  }

  return {
    kept: clusters.length,
    suppressed: suppressed.size,
    clusters,
  };
}
