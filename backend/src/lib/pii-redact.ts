/**
 * PII / Secret Redaction — scans text for sensitive patterns and replaces with [REDACTED].
 * Applied to finding evidence, payloads, and notes before storage.
 */

interface RedactionResult {
  text: string;
  redacted: boolean;
  patterns_matched: string[];
}

const PATTERNS: Array<{ name: string; regex: RegExp }> = [
  { name: "AWS Access Key",      regex: /AKIA[0-9A-Z]{16}/g },
  { name: "AWS Secret Key",      regex: /(?<![A-Za-z0-9])[A-Za-z0-9+/]{40}(?![A-Za-z0-9+/])/g },
  { name: "Generic API Key",     regex: /(?:api[_-]?key|apikey|api[_-]?token)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})/gi },
  { name: "Bearer Token",        regex: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/g },
  { name: "Basic Auth Header",   regex: /Basic\s+[A-Za-z0-9+/]+=*/g },
  { name: "Password in URL",     regex: /(?:password|passwd|pwd)\s*[:=]\s*['"]?([^\s'"&]{4,})/gi },
  { name: "Credit Card (Visa)",  regex: /\b4[0-9]{12}(?:[0-9]{3})?\b/g },
  { name: "Credit Card (MC)",    regex: /\b5[1-5][0-9]{14}\b/g },
  { name: "Credit Card (Amex)",  regex: /\b3[47][0-9]{13}\b/g },
  { name: "SSN",                 regex: /\b\d{3}-\d{2}-\d{4}\b/g },
  { name: "Private Key",         regex: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----/g },
  { name: "JWT Token",           regex: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g },
  { name: "GitHub Token",        regex: /ghp_[A-Za-z0-9]{36}/g },
  { name: "Slack Token",         regex: /xox[baprs]-([0-9a-zA-Z]{10,48})/g },
  { name: "Connection String",   regex: /(?:mongodb|postgres|mysql|redis):\/\/[^\s'"]+/gi },
  { name: "Email Address",       regex: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g },
];

export function redactPii(input: string): RedactionResult {
  if (!input || typeof input !== "string") {
    return { text: input, redacted: false, patterns_matched: [] };
  }

  let text = input;
  const matched: string[] = [];

  for (const { name, regex } of PATTERNS) {
    const before = text;
    text = text.replace(regex, `[REDACTED:${name.replace(/\s+/g, "_").toUpperCase()}]`);
    if (text !== before) matched.push(name);
  }

  return { text, redacted: matched.length > 0, patterns_matched: matched };
}

export function redactObject<T extends Record<string, unknown>>(
  obj: T,
  fields: string[]
): { obj: T; redacted: boolean; patterns: string[] } {
  const result = { ...obj } as Record<string, unknown>;
  let anyRedacted = false;
  const allPatterns: string[] = [];

  for (const field of fields) {
    const val = result[field];
    if (typeof val === "string") {
      const r = redactPii(val);
      result[field] = r.text;
      if (r.redacted) {
        anyRedacted = true;
        allPatterns.push(...r.patterns_matched);
      }
    }
  }

  return { obj: result as T, redacted: anyRedacted, patterns: [...new Set(allPatterns)] };
}

// Fields in findings that should be redacted before storage
export const FINDING_SENSITIVE_FIELDS = [
  "evidence", "request_headers", "response_headers",
  "payload", "raw_request", "raw_response", "description",
];
