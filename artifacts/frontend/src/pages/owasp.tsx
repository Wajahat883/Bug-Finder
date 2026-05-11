import { useQuery } from "@tanstack/react-query";
import { useState, useMemo } from "react";
import { useLocation } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import {
  AreaChart, Area, ResponsiveContainer, Tooltip as RTooltip,
} from "recharts";
import {
  ShieldCheck, ShieldAlert, AlertTriangle, ChevronRight,
  ChevronDown, ExternalLink, Search, X, TrendingDown, TrendingUp,
} from "lucide-react";

// ── Static OWASP data ─────────────────────────────────────────────────────

const OWASP_TOP10 = [
  { id: "A01:2021", short: "A01", name: "Broken Access Control",                  url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/" },
  { id: "A02:2021", short: "A02", name: "Cryptographic Failures",                 url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/" },
  { id: "A03:2021", short: "A03", name: "Injection",                              url: "https://owasp.org/Top10/A03_2021-Injection/" },
  { id: "A04:2021", short: "A04", name: "Insecure Design",                        url: "https://owasp.org/Top10/A04_2021-Insecure_Design/" },
  { id: "A05:2021", short: "A05", name: "Security Misconfiguration",              url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/" },
  { id: "A06:2021", short: "A06", name: "Vulnerable and Outdated Components",     url: "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/" },
  { id: "A07:2021", short: "A07", name: "Identification and Authentication Failures", url: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" },
  { id: "A08:2021", short: "A08", name: "Software and Data Integrity Failures",   url: "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/" },
  { id: "A09:2021", short: "A09", name: "Security Logging and Monitoring Failures", url: "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/" },
  { id: "A10:2021", short: "A10", name: "Server-Side Request Forgery",            url: "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery/" },
];

// Which categories are covered by our scanner modules
const SCANNER_COVERED = new Set(["A01:2021","A02:2021","A03:2021","A05:2021","A06:2021","A07:2021"]);

const SEV_ORDER = ["critical","high","medium","low","info"] as const;
const SEV_COLOR: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22d3ee", info: "#6b7280",
};

// ── Sparkline component ───────────────────────────────────────────────────

function Sparkline({ data, color }: { data: number[]; color: string }) {
  const chartData = data.map((v, i) => ({ i, v }));
  return (
    <ResponsiveContainer width={100} height={32}>
      <AreaChart data={chartData} margin={{ top: 2, bottom: 2, left: 0, right: 0 }}>
        <defs>
          <linearGradient id={`sg-${color.replace("#","")}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.4} />
            <stop offset="100%" stopColor={color} stopOpacity={0} />
          </linearGradient>
        </defs>
        <Area type="monotone" dataKey="v" stroke={color} strokeWidth={1.5}
          fill={`url(#sg-${color.replace("#","")})`} dot={false} />
        <RTooltip content={() => null} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

// ── Category drill-down panel ─────────────────────────────────────────────

function DrillPanel({
  category,
  findings,
  onClose,
}: {
  category: typeof OWASP_TOP10[0];
  findings: any[];
  onClose: () => void;
}) {
  const [, setLocation] = useLocation();
  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div
        className="h-full w-full max-w-lg border-l border-border bg-card shadow-2xl overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="sticky top-0 bg-card border-b border-border px-5 py-4 flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-muted-foreground">{category.short}</span>
              <span className="font-semibold">{category.name}</span>
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">{findings.length} findings</p>
          </div>
          <div className="flex items-center gap-2">
            <a href={category.url} target="_blank" rel="noopener noreferrer"
              className="text-muted-foreground hover:text-foreground">
              <ExternalLink className="w-4 h-4" />
            </a>
            <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        <div className="p-5 space-y-3">
          {findings.length === 0 ? (
            <div className="py-10 text-center text-muted-foreground text-sm">
              No findings for this category.
            </div>
          ) : (
            findings.map((f) => (
              <div
                key={f.id}
                className="p-3 rounded-lg border border-border hover:border-primary/30 cursor-pointer transition-colors"
                onClick={() => setLocation(`/findings/${f.id}`)}
              >
                <div className="flex items-center gap-2 mb-1">
                  <span
                    className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded"
                    style={{ background: `${SEV_COLOR[f.severity] ?? "#6b7280"}22`, color: SEV_COLOR[f.severity] ?? "#6b7280" }}
                  >
                    {f.severity}
                  </span>
                  <span className="text-sm font-medium">{f.title}</span>
                </div>
                <p className="text-xs text-muted-foreground font-mono">{f.endpoint}</p>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────

export default function OWASPPage() {
  const [expanded, setExpanded] = useState<string | null>(null);
  const [drillId, setDrillId] = useState<string | null>(null);
  const [drillFindings, setDrillFindings] = useState<any[]>([]);
  const [drillLoading, setDrillLoading] = useState(false);

  const { data: report } = useQuery<any>({
    queryKey: ["/api/compliance/report"],
    queryFn: () => fetch("/api/compliance/report", { credentials: "include" }).then(r => r.json()),
  });

  const { data: allFindings = [] } = useQuery<any[]>({
    queryKey: ["/api/findings", "owasp"],
    queryFn: () => fetch("/api/findings?limit=500", { credentials: "include" }).then(r => r.json()).then(d => Array.isArray(d) ? d : d?.items ?? []),
  });

  const { data: remediations = [] } = useQuery<any[]>({
    queryKey: ["/api/remediations"],
    queryFn: () => fetch("/api/remediations?limit=200", { credentials: "include" }).then(r => r.json()).then(d => Array.isArray(d) ? d : d?.items ?? []),
  });

  // Build weekly sparkline data per OWASP category from findings created_at
  const sparklineData = useMemo(() => {
    const now = Date.now();
    const result: Record<string, number[]> = {};
    for (const cat of OWASP_TOP10) {
      const weeks: number[] = [];
      for (let i = 7; i >= 0; i--) {
        const wStart = new Date(now - (i + 1) * 7 * 24 * 60 * 60 * 1000);
        const wEnd = new Date(now - i * 7 * 24 * 60 * 60 * 1000);
        const count = (report?.owasp_top10 ?? []).find((o: any) => o.id === cat.id)?.findings_count
          ? allFindings.filter(f => {
              const d = new Date(f.created_at);
              return d >= wStart && d < wEnd;
            }).length
          : 0;
        weeks.push(count);
      }
      result[cat.id] = weeks;
    }
    return result;
  }, [allFindings, report]);

  // Build per-category heatmap: count by severity
  const heatmapData = useMemo(() => {
    const REVERSE_MAP: Record<string, string[]> = {
      "A01:2021": ["Broken Access Control","IDOR","Path Traversal"],
      "A02:2021": ["TLS","Cryptographic","Secrets Exposure"],
      "A03:2021": ["Injection","Template Injection","SQLi","XSS","Cross-Site Scripting","Request Smuggling","Header Injection"],
      "A04:2021": ["File Upload","Insecure Design"],
      "A05:2021": ["Security Misconfiguration","CORS","Information Disclosure","API Security","Attack Surface","WebSocket Security"],
      "A06:2021": ["Known Vulnerability","Supply Chain"],
      "A07:2021": ["Authentication","JWT Security","Session Management"],
      "A08:2021": ["Software Integrity"],
      "A09:2021": ["Security Logging"],
      "A10:2021": ["SSRF","Server-Side Request Forgery"],
    };
    const result: Record<string, Record<string, number>> = {};
    for (const cat of OWASP_TOP10) {
      const cats = REVERSE_MAP[cat.id] ?? [];
      const catFindings = allFindings.filter(f => cats.includes(f.category ?? ""));
      result[cat.id] = {};
      for (const sev of SEV_ORDER) {
        result[cat.id][sev] = catFindings.filter(f => f.severity === sev).length;
      }
    }
    return result;
  }, [allFindings]);

  // Remediation rate per OWASP category
  const remediationRate = useMemo(() => {
    const REVERSE_MAP: Record<string, string[]> = {
      "A01:2021": ["Broken Access Control","IDOR","Path Traversal"],
      "A02:2021": ["TLS","Cryptographic","Secrets Exposure"],
      "A03:2021": ["Injection","Template Injection","SQLi","XSS","Cross-Site Scripting"],
      "A04:2021": ["File Upload","Insecure Design"],
      "A05:2021": ["Security Misconfiguration","CORS","Information Disclosure","API Security"],
      "A06:2021": ["Known Vulnerability","Supply Chain"],
      "A07:2021": ["Authentication","JWT Security","Session Management"],
      "A08:2021": [], "A09:2021": [], "A10:2021": [],
    };
    const result: Record<string, { total: number; fixed: number }> = {};
    const resolvedFindingIds = new Set(
      remediations.filter(r => r.status === "resolved").map(r => r.finding_id).filter(Boolean)
    );
    for (const cat of OWASP_TOP10) {
      const cats = REVERSE_MAP[cat.id] ?? [];
      const catFindings = allFindings.filter(f => cats.includes(f.category ?? ""));
      result[cat.id] = {
        total: catFindings.length,
        fixed: catFindings.filter(f => resolvedFindingIds.has(f.id)).length,
      };
    }
    return result;
  }, [allFindings, remediations]);

  // Benchmark score (0-100): severity-weighted across all 10 categories
  const benchmarkScore = useMemo(() => {
    if (!report?.owasp_top10) return null;
    const WEIGHTS = { critical: 20, high: 10, medium: 5, low: 2 };
    let totalPenalty = 0;
    for (const cat of report.owasp_top10) {
      const h = heatmapData[cat.id] ?? {};
      totalPenalty += (h.critical ?? 0) * WEIGHTS.critical + (h.high ?? 0) * WEIGHTS.high
        + (h.medium ?? 0) * WEIGHTS.medium + (h.low ?? 0) * WEIGHTS.low;
    }
    return Math.max(0, Math.min(100, 100 - Math.round(totalPenalty / 2)));
  }, [report, heatmapData]);

  const owaspItems = report?.owasp_top10 ?? OWASP_TOP10.map(c => ({ ...c, status: "pass", findings_count: 0, critical: 0, high: 0 }));
  const failCount = owaspItems.filter((o: any) => o.status === "fail").length;
  const coverageGaps = OWASP_TOP10.filter(c => !SCANNER_COVERED.has(c.id));

  async function openDrill(catId: string) {
    setDrillId(catId);
    setDrillLoading(true);
    try {
      const res = await fetch(`/api/compliance/owasp/findings/${catId}`, { credentials: "include" });
      setDrillFindings(await res.json());
    } catch { setDrillFindings([]); }
    setDrillLoading(false);
  }

  const drillCat = OWASP_TOP10.find(c => c.id === drillId);

  // Max cell count for heatmap intensity
  const maxCell = useMemo(() => {
    let m = 1;
    for (const v of Object.values(heatmapData)) {
      for (const n of Object.values(v)) if (n > m) m = n;
    }
    return m;
  }, [heatmapData]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
          <ShieldCheck className="w-7 h-7" />
          OWASP Top 10 — 2021
        </h1>
        <p className="text-muted-foreground mt-1">
          Coverage heatmap, trend sparklines, and remediation rates per category.
        </p>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card className="p-4">
          <div className="text-3xl font-bold" style={{ color: benchmarkScore !== null ? (benchmarkScore >= 80 ? "#22c55e" : benchmarkScore >= 50 ? "#eab308" : "#ef4444") : "hsl(var(--muted-foreground))" }}>
            {benchmarkScore ?? "—"}
          </div>
          <div className="text-xs text-muted-foreground mt-0.5">Benchmark Score</div>
        </Card>
        <Card className="p-4">
          <div className="text-3xl font-bold text-green-400">{10 - failCount}</div>
          <div className="text-xs text-muted-foreground mt-0.5">Categories Passed</div>
        </Card>
        <Card className="p-4">
          <div className="text-3xl font-bold text-red-400">{failCount}</div>
          <div className="text-xs text-muted-foreground mt-0.5">Categories Failed</div>
        </Card>
        <Card className="p-4">
          <div className="text-3xl font-bold text-yellow-400">{coverageGaps.length}</div>
          <div className="text-xs text-muted-foreground mt-0.5">Coverage Gaps</div>
        </Card>
      </div>

      {/* Coverage gaps warning */}
      {coverageGaps.length > 0 && (
        <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/8 p-4">
          <div className="flex items-start gap-2 mb-2">
            <AlertTriangle className="w-4 h-4 text-yellow-500 flex-shrink-0 mt-0.5" />
            <span className="text-sm font-semibold text-yellow-500">Scanner Coverage Gaps</span>
          </div>
          <p className="text-xs text-muted-foreground mb-2">
            These OWASP categories are not actively tested by any scanner module. A clean result here does NOT mean you are safe.
          </p>
          <div className="flex flex-wrap gap-2">
            {coverageGaps.map(c => (
              <span key={c.id} className="text-xs font-mono px-2 py-0.5 rounded border border-yellow-500/30 bg-yellow-500/10 text-yellow-400">
                {c.short} — {c.name}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Heatmap header */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">Coverage Heatmap</CardTitle>
          <p className="text-xs text-muted-foreground">Finding density per category × severity. Darker = more findings.</p>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr>
                <th className="text-left pb-2 text-muted-foreground font-normal w-40">Category</th>
                {SEV_ORDER.map(s => (
                  <th key={s} className="pb-2 text-center capitalize text-muted-foreground font-normal px-1" style={{ color: SEV_COLOR[s] }}>
                    {s}
                  </th>
                ))}
                <th className="pb-2 text-center text-muted-foreground font-normal px-2">Trend</th>
                <th className="pb-2 text-center text-muted-foreground font-normal px-2">Fix Rate</th>
                <th className="pb-2 w-6" />
              </tr>
            </thead>
            <tbody>
              {OWASP_TOP10.map((cat) => {
                const item = owaspItems.find((o: any) => o.id === cat.id);
                const sev = heatmapData[cat.id] ?? {};
                const rem = remediationRate[cat.id] ?? { total: 0, fixed: 0 };
                const fixPct = rem.total > 0 ? Math.round((rem.fixed / rem.total) * 100) : 0;
                const spark = sparklineData[cat.id] ?? [0,0,0,0,0,0,0,0];
                const trend = spark[spark.length - 1] - spark[0];
                const isOpen = expanded === cat.id;
                const passed = item?.status === "pass";

                return (
                  <>
                    <tr
                      key={cat.id}
                      className="hover:bg-accent/20 cursor-pointer transition-colors border-t border-border"
                      onClick={() => setExpanded(isOpen ? null : cat.id)}
                    >
                      <td className="py-2 pr-3">
                        <div className="flex items-center gap-2">
                          {passed
                            ? <ShieldCheck className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
                            : <ShieldAlert className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
                          }
                          <span className="font-mono text-muted-foreground">{cat.short}</span>
                          <span className="truncate max-w-[140px]" title={cat.name}>{cat.name}</span>
                          {!SCANNER_COVERED.has(cat.id) && (
                            <span className="text-[9px] px-1 py-0.5 rounded bg-yellow-500/20 text-yellow-400">gap</span>
                          )}
                        </div>
                      </td>
                      {SEV_ORDER.map(s => {
                        const n = sev[s] ?? 0;
                        const intensity = maxCell > 0 ? n / maxCell : 0;
                        return (
                          <td key={s} className="py-2 px-1 text-center">
                            <div
                              className="mx-auto w-8 h-7 rounded flex items-center justify-center text-xs font-bold transition-all"
                              style={{
                                background: n > 0 ? `${SEV_COLOR[s]}${Math.round(15 + intensity * 50).toString(16).padStart(2,"0")}` : "transparent",
                                color: n > 0 ? SEV_COLOR[s] : "hsl(var(--muted-foreground))",
                                border: n > 0 ? `1px solid ${SEV_COLOR[s]}40` : "1px solid transparent",
                              }}
                            >
                              {n > 0 ? n : "·"}
                            </div>
                          </td>
                        );
                      })}
                      <td className="py-2 px-2">
                        <div className="flex items-center gap-1">
                          <Sparkline data={spark} color={passed ? "#22c55e" : "#ef4444"} />
                          {trend > 0
                            ? <TrendingUp className="w-3 h-3 text-red-400 flex-shrink-0" />
                            : trend < 0
                              ? <TrendingDown className="w-3 h-3 text-green-400 flex-shrink-0" />
                              : null
                          }
                        </div>
                      </td>
                      <td className="py-2 px-2">
                        {rem.total > 0 ? (
                          <div className="w-20">
                            <div className="flex justify-between mb-0.5">
                              <span className="text-[10px] text-muted-foreground">{fixPct}%</span>
                              <span className="text-[10px] text-muted-foreground">{rem.fixed}/{rem.total}</span>
                            </div>
                            <Progress value={fixPct} className="h-1.5" />
                          </div>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </td>
                      <td className="py-2">
                        <div className="flex items-center gap-1">
                          <button
                            className="text-muted-foreground hover:text-primary transition-colors"
                            onClick={(e) => { e.stopPropagation(); openDrill(cat.id); }}
                            title="View findings"
                          >
                            <Search className="w-3.5 h-3.5" />
                          </button>
                          {isOpen ? <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" /> : <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" />}
                        </div>
                      </td>
                    </tr>
                    {isOpen && (
                      <tr key={`${cat.id}-exp`} className="bg-accent/10">
                        <td colSpan={9} className="px-4 py-3">
                          <div className="flex items-start gap-4">
                            <div className="flex-1">
                              <p className="text-xs text-muted-foreground mb-2">
                                {item?.findings_count ?? 0} finding(s) in this category.
                                {rem.total > 0 && ` ${rem.fixed} remediated (${fixPct}%).`}
                              </p>
                              <div className="flex gap-2">
                                <a href={cat.url} target="_blank" rel="noopener noreferrer">
                                  <Button size="sm" variant="outline" className="h-7 text-xs gap-1">
                                    <ExternalLink className="w-3 h-3" /> OWASP Docs
                                  </Button>
                                </a>
                                <Button size="sm" variant="outline" className="h-7 text-xs"
                                  onClick={() => openDrill(cat.id)}>
                                  <Search className="w-3 h-3 mr-1" /> View Findings
                                </Button>
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                );
              })}
            </tbody>
          </table>
        </CardContent>
      </Card>

      {/* Drill-down panel */}
      {drillId && drillCat && (
        <DrillPanel
          category={drillCat}
          findings={drillLoading ? [] : drillFindings}
          onClose={() => setDrillId(null)}
        />
      )}

      <p className="text-xs text-center text-muted-foreground">
        Based on {allFindings.length} total findings · Scanner covers {SCANNER_COVERED.size}/10 OWASP categories ·
        Zero findings in an uncovered category does not indicate compliance
      </p>
    </div>
  );
}
