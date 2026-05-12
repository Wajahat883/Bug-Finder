import { logger } from "../lib/logger";

interface Finding {
  title: string;
  category: string;
  severity: string;
  endpoint: string;
  description: string;
  cwe_id?: string;
  cvss_score?: number;
  evidence?: string;
  recommended_fix?: string;
}

interface AiPatch {
  language: string;
  patch_code: string;
  explanation: string;
  references: string[];
}

const LANGUAGE_HINTS: Record<string, string[]> = {
  "node": ["express", "node", "javascript", "typescript", "npm", "require"],
  "python": ["flask", "django", "fastapi", "python", ".py", "pip"],
  "java": ["spring", "java", "maven", "gradle", ".java", "servlet"],
  "php": ["laravel", "wordpress", "php", ".php", "composer"],
  "ruby": ["rails", "ruby", ".rb", "gem"],
  "go": ["golang", "go", ".go", "gin", "fiber"],
};

function detectLanguage(finding: Finding): string {
  const haystack = `${finding.endpoint} ${finding.description} ${finding.evidence ?? ""}`.toLowerCase();
  for (const [lang, hints] of Object.entries(LANGUAGE_HINTS)) {
    if (hints.some(h => haystack.includes(h))) return lang;
  }
  return "generic";
}

export async function generateCodePatch(finding: Finding): Promise<AiPatch | null> {
  const apiKey = process.env["OPENCODE_API_KEY"] ?? process.env["OPENAI_API_KEY"];
  if (!apiKey) {
    logger.warn("AI remediation: no API key configured (OPENCODE_API_KEY or OPENAI_API_KEY)");
    return null;
  }

  const lang = detectLanguage(finding);

  const prompt = `You are a security engineer generating a code fix for a vulnerability.

Vulnerability:
- Title: ${finding.title}
- Category: ${finding.category}
- Severity: ${finding.severity}
- CWE: ${finding.cwe_id ?? "N/A"}
- CVSS: ${finding.cvss_score ?? "N/A"}
- Endpoint: ${finding.endpoint}
- Description: ${finding.description}
- Existing recommendation: ${finding.recommended_fix ?? "None"}
- Detected language/framework: ${lang}

Respond ONLY with a JSON object (no markdown, no extra text):
{
  "language": "<language>",
  "patch_code": "<complete corrected code snippet or diff>",
  "explanation": "<1-2 sentence explanation of what the fix does and why>",
  "references": ["<url1>", "<url2>"]
}`;

  try {
    const { default: OpenAI } = await import("openai");
    const openai = new OpenAI({
      apiKey,
      baseURL: process.env["OPENCODE_API_BASE"] ?? undefined,
      timeout: 30000,
    });

    const model = process.env["OPENCODE_MODEL"] ?? process.env["OPENAI_MODEL"] ?? "gpt-4o-mini";
    const completion = await openai.chat.completions.create({
      model,
      max_tokens: 800,
      temperature: 0.2,
      messages: [{ role: "user", content: prompt }],
      stream: false,
    });

    const raw = completion.choices[0]?.message?.content ?? "";
    const parsed = JSON.parse(raw) as AiPatch;
    return parsed;
  } catch (err) {
    logger.warn({ err }, "AI remediation patch generation failed");
    return null;
  }
}
