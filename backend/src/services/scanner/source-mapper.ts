import { logger } from "../../lib/logger";

interface SourceLocation {
  file: string;
  line?: number;
  column?: number;
  snippet?: string;
  confidence: number;
}

interface RepoIndex {
  repo: string;
  files: Map<string, string>;
  indexedAt: number;
}

const repoCache: Map<string, RepoIndex> = new Map();

export async function indexRepo(repoUrl: string, token?: string): Promise<RepoIndex | null> {
  if (repoCache.has(repoUrl)) {
    const cached = repoCache.get(repoUrl)!;
    if (Date.now() - cached.indexedAt < 3600000) return cached;
  }

  try {
    const headers: Record<string, string> = { Accept: "application/vnd.github.v3+json" };
    if (token) headers["Authorization"] = `Bearer ${token}`;

    const repoMatch = repoUrl.match(/github\.com\/([^/]+)\/([^/]+?)(?:\.git)?$/);
    if (!repoMatch) return null;

    const [, owner, repo] = repoMatch;
    const apiUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/main?recursive=1`;

    const treeRes = await fetch(apiUrl, { headers });
    if (!treeRes.ok) return null;

    const tree = await treeRes.json() as { tree: Array<{ path: string }> };
    const index: RepoIndex = {
      repo: `${owner}/${repo}`,
      files: new Map(),
      indexedAt: Date.now(),
    };

    const sourceFiles = tree.tree.filter(f =>
      /\.(ts|tsx|js|jsx|py|go|java|rb|php|cs|swift|kt|rs)$/.test(f.path)
    ).slice(0, 200);

    for (const file of sourceFiles) {
      const contentUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${file.path}`;
      try {
        const contentRes = await fetch(contentUrl, { headers });
        if (!contentRes.ok) continue;
        const contentData = await contentRes.json() as { content?: string; encoding?: string };
        if (contentData.content && contentData.encoding === "base64") {
          index.files.set(file.path, Buffer.from(contentData.content, "base64").toString("utf-8"));
        }
      } catch { /* skip unreadable */ }
    }

    repoCache.set(repoUrl, index);
    logger.info({ repo: index.repo, files: index.files.size }, "Repository indexed");
    return index;
  } catch (err) {
    logger.warn({ err, repoUrl }, "Failed to index repository");
    return null;
  }
}

export function findSourceLocation(
  finding: {
    title: string;
    endpoint: string;
    category: string;
    description: string;
    severity: string;
  },
  repoIndex: RepoIndex
): SourceLocation | null {
  const searchTerms = extractSearchTerms(finding);
  let bestMatch: SourceLocation | null = null;
  let bestScore = 0;

  for (const [filePath, content] of repoIndex.files) {
    const lines = content.split("\n");

    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
      const line = lines[lineNum];
      const score = scoreLine(line, searchTerms, finding);

      if (score > bestScore) {
        bestScore = score;
        const snippet = lines.slice(Math.max(0, lineNum - 2), Math.min(lines.length, lineNum + 3)).join("\n");
        bestMatch = {
          file: filePath,
          line: lineNum + 1,
          snippet,
          confidence: Math.min(1, score / 20),
        };
      }
    }
  }

  return bestMatch && bestMatch.confidence >= 0.3 ? bestMatch : null;
}

function extractSearchTerms(finding: {
  title: string;
  endpoint: string;
  category: string;
  description: string;
}): string[] {
  const terms: string[] = [];

  const epPath = finding.endpoint.replace(/^https?:\/\/[^/]+/, "").split("?")[0];
  terms.push(epPath);

  const epParts = epPath.split("/").filter(Boolean);
  terms.push(...epParts);

  const titleWords = finding.title.toLowerCase().split(/\s+/);
  const securityTerms: Record<string, string[]> = {
    "sql injection": ["query", "raw", "execute", "sql", "where", "select"],
    "xss": ["innerhtml", "dangerouslysetinnerhtml", "insertadjacenthtml", "document.write", "eval"],
    "jwt": ["jwt", "sign", "verify", "jsonwebtoken", "secret"],
    "cors": ["cors", "access-control", "origin"],
    "csrf": ["csrf", "token", "xsrf"],
    "idor": [":id", "params.id", "req.params"],
    "path traversal": ["readfile", "readfilesync", "fs.read", "require"],
    "rate limit": ["ratelimit", "rate-limit", "limiter"],
    "security headers": ["helmet", "csp", "hsts", "x-frame"],
    "file upload": ["multer", "upload", "formidable", "file"],
    "injection": ["$regex", ".find({", ".updateOne({", "$where"],
  };

  for (const [key, kws] of Object.entries(securityTerms)) {
    if (titleWords.some(w => key.includes(w) || w.includes(key.slice(0, 4)))) {
      terms.push(...kws);
    }
  }

  terms.push(finding.category.toLowerCase());

  return [...new Set(terms.filter(t => t.length > 1))];
}

function scoreLine(line: string, searchTerms: string[], finding: { severity: string }): number {
  let score = 0;
  const lower = line.toLowerCase().trim();

  if (lower.startsWith("//") || lower.startsWith("#") || lower.startsWith("/*")) return 0;

  for (const term of searchTerms) {
    if (lower.includes(term.toLowerCase())) score += 3;
  }

  const sqlPatterns = [
    /\.query\s*\(/i, /\.execute\s*\(/i, /\bsql\b/i, /\$where/i,
    /db\.query/i, /pool\.query/i, /client\.query/i,
    /\+\s*req\./i, /\$\{.*req\./i, /\.find\(\{.*\}/i,
  ];
  for (const pat of sqlPatterns) {
    if (pat.test(line)) score += 5;
  }

  const xssPatterns = [
    /innerHTML/i, /dangerouslySetInnerHTML/i, /insertAdjacentHTML/i,
    /document\.write/i, /eval\(/i, /v-html/i, /bypassSecurity/i,
  ];
  for (const pat of xssPatterns) {
    if (pat.test(line)) score += 5;
  }

  if (finding.severity === "critical") score *= 1.5;
  if (finding.severity === "high") score *= 1.3;
  if (finding.severity === "low") score *= 0.8;

  return Math.round(score);
}

export function formatSourceLocation(loc: SourceLocation): string {
  let result = `${loc.file}`;
  if (loc.line) result += `:${loc.line}`;
  return result;
}

export function getRepoUrl(targetUrl: string): string | null {
  try {
    const url = new URL(targetUrl);
    if (url.hostname.endsWith("github.io")) {
      const parts = url.hostname.replace(".github.io", "").split(".");
      if (parts.length >= 1) return `https://github.com/${parts[0]}/${parts[0]}.github.io`;
    }
    return null;
  } catch {
    return null;
  }
}
