/**
 * Compliance Framework Mapper — maps CWE IDs to regulatory frameworks.
 * Supports: PCI-DSS v4, HIPAA, SOC2, ISO 27001, NIST SP 800-53, GDPR, OWASP Top 10.
 */

export type ComplianceFramework =
  | "PCI-DSS"
  | "HIPAA"
  | "SOC2"
  | "ISO-27001"
  | "NIST-800-53"
  | "GDPR"
  | "OWASP-A01"
  | "OWASP-A02"
  | "OWASP-A03"
  | "OWASP-A04"
  | "OWASP-A05"
  | "OWASP-A06"
  | "OWASP-A07"
  | "OWASP-A08"
  | "OWASP-A09"
  | "OWASP-A10";

// CWE → compliance frameworks
const CWE_MAP: Record<string, ComplianceFramework[]> = {
  // Injection
  "CWE-89":   ["PCI-DSS", "OWASP-A03", "NIST-800-53", "SOC2"],
  "CWE-79":   ["PCI-DSS", "OWASP-A03", "NIST-800-53", "SOC2"],
  "CWE-78":   ["PCI-DSS", "OWASP-A03", "NIST-800-53"],
  "CWE-77":   ["OWASP-A03", "NIST-800-53"],
  "CWE-90":   ["OWASP-A03"],
  "CWE-917":  ["OWASP-A03"],

  // Auth / Session
  "CWE-287":  ["PCI-DSS", "HIPAA", "OWASP-A07", "ISO-27001", "SOC2"],
  "CWE-306":  ["PCI-DSS", "HIPAA", "OWASP-A07", "NIST-800-53"],
  "CWE-307":  ["PCI-DSS", "OWASP-A07"],
  "CWE-521":  ["PCI-DSS", "OWASP-A07", "NIST-800-53"],
  "CWE-613":  ["PCI-DSS", "OWASP-A07", "HIPAA"],
  "CWE-798":  ["PCI-DSS", "OWASP-A07", "NIST-800-53"],

  // Access Control
  "CWE-862":  ["PCI-DSS", "OWASP-A01", "NIST-800-53", "ISO-27001"],
  "CWE-863":  ["PCI-DSS", "OWASP-A01", "NIST-800-53"],
  "CWE-284":  ["HIPAA", "OWASP-A01", "SOC2"],
  "CWE-285":  ["OWASP-A01", "NIST-800-53"],

  // Cryptography
  "CWE-327":  ["PCI-DSS", "HIPAA", "OWASP-A02", "GDPR", "ISO-27001"],
  "CWE-326":  ["PCI-DSS", "HIPAA", "OWASP-A02", "GDPR"],
  "CWE-295":  ["PCI-DSS", "OWASP-A02", "NIST-800-53"],
  "CWE-330":  ["PCI-DSS", "OWASP-A02"],

  // Sensitive Data Exposure
  "CWE-200":  ["PCI-DSS", "HIPAA", "GDPR", "OWASP-A02", "SOC2"],
  "CWE-312":  ["PCI-DSS", "HIPAA", "GDPR", "OWASP-A02"],
  "CWE-313":  ["HIPAA", "GDPR", "OWASP-A02"],
  "CWE-319":  ["PCI-DSS", "HIPAA", "OWASP-A02", "GDPR"],

  // Security Misconfiguration
  "CWE-16":   ["OWASP-A05", "NIST-800-53", "SOC2"],

  // Vulnerable Components
  "CWE-1035": ["OWASP-A06", "NIST-800-53"],
  "CWE-937":  ["OWASP-A06"],

  // Logging / Monitoring
  "CWE-778":  ["PCI-DSS", "HIPAA", "OWASP-A09", "SOC2"],
  "CWE-779":  ["OWASP-A09"],

  // SSRF
  "CWE-918":  ["OWASP-A10", "NIST-800-53"],

  // XXE
  "CWE-611":  ["OWASP-A05", "OWASP-A08"],

  // Deserialization
  "CWE-502":  ["OWASP-A08", "NIST-800-53"],

  // Path Traversal
  "CWE-22":   ["PCI-DSS", "OWASP-A01", "NIST-800-53"],
  "CWE-23":   ["OWASP-A01"],

  // File Upload
  "CWE-434":  ["OWASP-A04", "PCI-DSS"],

  // CSRF
  "CWE-352":  ["OWASP-A01", "NIST-800-53"],

  // Open Redirect
  "CWE-601":  ["OWASP-A01"],
};

export function getComplianceTags(cweId: string | undefined | null): ComplianceFramework[] {
  if (!cweId) return [];
  const normalized = cweId.toUpperCase().replace(/^CWE-/i, "CWE-");
  return CWE_MAP[normalized] ?? [];
}

export function severityToRisk(severity: string): "critical" | "high" | "medium" | "low" | "info" {
  const s = severity?.toLowerCase();
  if (["critical", "high", "medium", "low", "info"].includes(s)) {
    return s as ReturnType<typeof severityToRisk>;
  }
  return "info";
}

// Framework display metadata
export const FRAMEWORK_META: Record<ComplianceFramework, { label: string; color: string; url?: string }> = {
  "PCI-DSS":     { label: "PCI-DSS v4", color: "#3b82f6", url: "https://www.pcisecuritystandards.org/" },
  "HIPAA":       { label: "HIPAA",      color: "#8b5cf6", url: "https://www.hhs.gov/hipaa" },
  "SOC2":        { label: "SOC 2",      color: "#06b6d4", url: "https://www.aicpa.org/soc2" },
  "ISO-27001":   { label: "ISO 27001",  color: "#10b981" },
  "NIST-800-53": { label: "NIST 800-53",color: "#f59e0b" },
  "GDPR":        { label: "GDPR",       color: "#ec4899", url: "https://gdpr.eu" },
  "OWASP-A01":   { label: "A01:2021",   color: "#ef4444" },
  "OWASP-A02":   { label: "A02:2021",   color: "#f97316" },
  "OWASP-A03":   { label: "A03:2021",   color: "#eab308" },
  "OWASP-A04":   { label: "A04:2021",   color: "#84cc16" },
  "OWASP-A05":   { label: "A05:2021",   color: "#22d3ee" },
  "OWASP-A06":   { label: "A06:2021",   color: "#6366f1" },
  "OWASP-A07":   { label: "A07:2021",   color: "#a855f7" },
  "OWASP-A08":   { label: "A08:2021",   color: "#ec4899" },
  "OWASP-A09":   { label: "A09:2021",   color: "#14b8a6" },
  "OWASP-A10":   { label: "A10:2021",   color: "#f43f5e" },
};
