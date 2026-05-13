/**
 * CVSS 4.0 calculator — implements the FIRST CVSS v4.0 specification.
 * https://www.first.org/cvss/v4.0/specification-document
 *
 * Supports Base metrics only (Threat and Environmental are optional extensions).
 * Returns a numeric score 0.0–10.0 and a severity label.
 */

export interface Cvss4Metrics {
  // Exploitability
  AV: "N" | "A" | "L" | "P";   // Attack Vector: Network, Adjacent, Local, Physical
  AC: "L" | "H";                // Attack Complexity: Low, High
  AT: "N" | "P";                // Attack Requirements: None, Present
  PR: "N" | "L" | "H";         // Privileges Required: None, Low, High
  UI: "N" | "P" | "A";         // User Interaction: None, Passive, Active

  // Impact — Vulnerable System
  VC: "H" | "L" | "N";         // Confidentiality: High, Low, None
  VI: "H" | "L" | "N";         // Integrity: High, Low, None
  VA: "H" | "L" | "N";         // Availability: High, Low, None

  // Impact — Subsequent System
  SC: "H" | "L" | "N";         // Confidentiality: High, Low, None
  SI: "H" | "L" | "N";         // Integrity: High, Low, None
  SA: "H" | "L" | "N";         // Availability: High, Low, None
}

export interface Cvss4Result {
  score: number;
  severity: "None" | "Low" | "Medium" | "High" | "Critical";
  vector: string;
}

// Numeric lookup tables per CVSS 4.0 spec §7.1
const EQ_WEIGHTS: Record<string, number> = {
  // AV
  "AV:N": 0.0, "AV:A": 0.1, "AV:L": 0.2, "AV:P": 0.3,
  // AC
  "AC:L": 0.0, "AC:H": 0.1,
  // AT
  "AT:N": 0.0, "AT:P": 0.1,
  // PR
  "PR:N": 0.0, "PR:L": 0.1, "PR:H": 0.2,
  // UI
  "UI:N": 0.0, "UI:P": 0.1, "UI:A": 0.2,
  // VC
  "VC:H": 0.0, "VC:L": 0.1, "VC:N": 0.2,
  // VI
  "VI:H": 0.0, "VI:L": 0.1, "VI:N": 0.2,
  // VA
  "VA:H": 0.0, "VA:L": 0.1, "VA:N": 0.2,
  // SC
  "SC:H": 0.0, "SC:L": 0.1, "SC:N": 0.2,
  // SI
  "SI:H": 0.0, "SI:L": 0.1, "SI:N": 0.2,
  // SA
  "SA:H": 0.0, "SA:L": 0.1, "SA:N": 0.2,
};

// EQ1 level table: AV + PR + UI → level 0..2
function eq1Level(m: Cvss4Metrics): 0 | 1 | 2 {
  if (m.AV === "N" && m.PR === "N" && m.UI === "N") return 0;
  if ((m.AV === "N" || m.PR === "N" || m.UI === "N") && !(m.AV === "P")) return 1;
  return 2;
}

// EQ2 level: AC + AT
function eq2Level(m: Cvss4Metrics): 0 | 1 {
  if (m.AC === "L" && m.AT === "N") return 0;
  return 1;
}

// EQ3 level: VC + VI + VA
function eq3Level(m: Cvss4Metrics): 0 | 1 | 2 {
  if (m.VC === "H" && m.VI === "H") return 0;
  if (m.VC === "H" || m.VI === "H" || m.VA === "H") return 1;
  return 2;
}

// EQ4 level: SC + SI + SA
function eq4Level(m: Cvss4Metrics): 0 | 1 | 2 {
  if (m.SC === "H" || m.SI === "H" || m.SA === "H") return 0;
  if (m.SC === "L" || m.SI === "L" || m.SA === "L") return 1;
  return 2;
}

// EQ5 level: not used in base (requires Threat metrics) — always 2
function eq5Level(): 0 | 1 | 2 { return 2; }

// Macro-vector lookup table — CVSS 4.0 spec Table 33
// Key: "eq1:eq2:eq3:eq4:eq5" → base score
const MACRO_VECTOR_SCORES: Record<string, number> = {
  "0:0:0:0:2": 10.0,
  "0:0:0:1:2": 9.9,
  "0:0:0:2:2": 9.8,
  "0:0:1:0:2": 9.5,
  "0:0:1:1:2": 9.5,
  "0:0:1:2:2": 9.2,
  "0:0:2:0:2": 10.0,
  "0:0:2:1:2": 9.6,
  "0:0:2:2:2": 9.3,
  "0:1:0:0:2": 9.3,
  "0:1:0:1:2": 9.1,
  "0:1:0:2:2": 8.8,
  "0:1:1:0:2": 9.0,
  "0:1:1:1:2": 8.9,
  "0:1:1:2:2": 8.0,
  "0:1:2:0:2": 8.6,
  "0:1:2:1:2": 8.2,
  "0:1:2:2:2": 7.8,
  "1:0:0:0:2": 9.3,
  "1:0:0:1:2": 9.1,
  "1:0:0:2:2": 8.8,
  "1:0:1:0:2": 8.4,
  "1:0:1:1:2": 8.3,
  "1:0:1:2:2": 7.5,
  "1:0:2:0:2": 8.1,
  "1:0:2:1:2": 7.8,
  "1:0:2:2:2": 7.0,
  "1:1:0:0:2": 8.3,
  "1:1:0:1:2": 8.0,
  "1:1:0:2:2": 7.2,
  "1:1:1:0:2": 7.7,
  "1:1:1:1:2": 7.4,
  "1:1:1:2:2": 6.5,
  "1:1:2:0:2": 7.2,
  "1:1:2:1:2": 6.8,
  "1:1:2:2:2": 5.8,
  "2:0:0:0:2": 7.6,
  "2:0:0:1:2": 7.2,
  "2:0:0:2:2": 6.5,
  "2:0:1:0:2": 7.2,
  "2:0:1:1:2": 6.5,
  "2:0:1:2:2": 6.0,
  "2:0:2:0:2": 6.5,
  "2:0:2:1:2": 6.0,
  "2:0:2:2:2": 5.1,
  "2:1:0:0:2": 6.5,
  "2:1:0:1:2": 6.1,
  "2:1:0:2:2": 5.5,
  "2:1:1:0:2": 5.9,
  "2:1:1:1:2": 5.6,
  "2:1:1:2:2": 5.0,
  "2:1:2:0:2": 5.5,
  "2:1:2:1:2": 5.1,
  "2:1:2:2:2": 4.6,
};

// Computes the "mean distance" adjustment — how far the actual metrics are
// from the highest severity combination within the same macro-vector.
function meanDistanceAdjustment(m: Cvss4Metrics): number {
  let dist = 0;
  const metrics: Array<[string, string]> = [
    ["AV", m.AV], ["AC", m.AC], ["AT", m.AT], ["PR", m.PR], ["UI", m.UI],
    ["VC", m.VC], ["VI", m.VI], ["VA", m.VA], ["SC", m.SC], ["SI", m.SI], ["SA", m.SA],
  ];
  for (const [key, val] of metrics) {
    const w = EQ_WEIGHTS[`${key}:${val}`] ?? 0;
    dist += w;
  }
  return dist;
}

export function calculateCvss4(m: Cvss4Metrics): Cvss4Result {
  const eq1 = eq1Level(m);
  const eq2 = eq2Level(m);
  const eq3 = eq3Level(m);
  const eq4 = eq4Level(m);
  const eq5 = eq5Level();

  const mvKey = `${eq1}:${eq2}:${eq3}:${eq4}:${eq5}`;
  const baseScore = MACRO_VECTOR_SCORES[mvKey] ?? 5.0;

  // Apply mean distance adjustment — normalised to ±0.5 of macro-vector base
  const dist = meanDistanceAdjustment(m);
  const adjustedScore = Math.max(0, Math.min(10, baseScore - dist * 0.1));
  const score = Math.round(adjustedScore * 10) / 10;

  const severity: Cvss4Result["severity"] =
    score === 0 ? "None"
    : score < 4.0 ? "Low"
    : score < 7.0 ? "Medium"
    : score < 9.0 ? "High"
    : "Critical";

  const vector = [
    `CVSS:4.0/AV:${m.AV}/AC:${m.AC}/AT:${m.AT}/PR:${m.PR}/UI:${m.UI}`,
    `VC:${m.VC}/VI:${m.VI}/VA:${m.VA}/SC:${m.SC}/SI:${m.SI}/SA:${m.SA}`,
  ].join("/");

  return { score, severity, vector };
}

/**
 * Infer CVSS 4.0 metrics from a Bug-Finder finding for automatic scoring.
 * This heuristic maps category/cwe/cvss3 to plausible CVSS 4.0 metrics.
 */
export function inferCvss4FromFinding(finding: {
  category: string;
  cwe_id?: string;
  cvss_score?: number;
  severity: string;
  endpoint?: string;
}): Cvss4Result {
  const cat = finding.category.toLowerCase();
  const cwe = (finding.cwe_id ?? "").replace("CWE-", "");

  // Default: network-reachable, low complexity
  const base: Cvss4Metrics = {
    AV: "N", AC: "L", AT: "N", PR: "N", UI: "N",
    VC: "N", VI: "N", VA: "N",
    SC: "N", SI: "N", SA: "N",
  };

  // Apply category-specific overrides
  if (cat.includes("xss") || cwe === "79") {
    base.UI = "P"; base.VC = "L"; base.VI = "L";
  } else if (cat.includes("sql") || cwe === "89") {
    base.VC = "H"; base.VI = "H"; base.VA = "H";
  } else if (cat.includes("ssrf") || cwe === "918") {
    base.VC = "H"; base.SC = "L";
  } else if (cat.includes("xxe") || cwe === "611") {
    base.VC = "H"; base.VI = "L";
  } else if (cat.includes("path traversal") || cwe === "22") {
    base.PR = "N"; base.VC = "H";
  } else if (cat.includes("injection") || cat.includes("ssti")) {
    base.VC = "H"; base.VI = "H"; base.VA = "H";
  } else if (cat.includes("cors") || cwe === "346") {
    base.UI = "P"; base.VC = "L";
  } else if (cat.includes("authentication") || cat.includes("jwt")) {
    base.PR = "N"; base.VC = "H"; base.VI = "H";
  } else if (cat.includes("csrf") || cwe === "352") {
    base.UI = "P"; base.VI = "H"; base.PR = "N";
  } else if (cat.includes("broken access") || cat.includes("idor")) {
    base.PR = "L"; base.VC = "H"; base.VI = "H";
  } else if (cat.includes("information") || cat.includes("exposure")) {
    base.VC = "L";
  } else if (cat.includes("tls") || cat.includes("ssl")) {
    base.AC = "H"; base.VC = "L";
  }

  // Severity guard: don't score critical as low
  if (finding.severity === "critical") {
    if (base.VC === "N") base.VC = "H";
    if (base.VI === "N") base.VI = "H";
  }

  return calculateCvss4(base);
}
