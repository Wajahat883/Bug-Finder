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
  Download, RefreshCw, LayoutGrid, Table2, Filter, CheckCircle2,
  XCircle, AlertCircle, Lock, FileText, Sparkles, ArrowUpRight,
  Clock, Activity,
} from "lucide-react";

// ── Static OWASP data ──────────────────────────────────────────────────────────

const OWASP_TOP10 = [
  { id: "A01:2021", short: "A01", name: "Broken Access Control",              desc: "Access control enforces policy so users cannot act outside their intended permissions. Failures lead to unauthorized disclosure, modification, or destruction of data.",        url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/" },
  { id: "A02:2021", short: "A02", name: "Cryptographic Failures",             desc: "Protects data at rest and in transit from cryptographic weaknesses and misconfigurations. Previously known as Sensitive Data Exposure.",                                       url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/" },
  { id: "A03:2021", short: "A03", name: "Injection",                          desc: "Hostile data sent to an interpreter via SQL, OS, LDAP, or other queries. Attacker's data can trick the interpreter into executing unintended commands.",                       url: "https://owasp.org/Top10/A03_2021-Injection/" },
  { id: "A04:2021", short: "A04", name: "Insecure Design",                    desc: "Design flaws that cannot be fixed by perfect implementation. Requires threat modeling, secure design patterns, and reference architectures.",                                    url: "https://owasp.org/Top10/A04_2021-Insecure_Design/" },
  { id: "A05:2021", short: "A05", name: "Security Misconfiguration",          desc: "Missing hardening, insecure defaults, open cloud storage, verbose error messages, or outdated software creates exploitable entry points.",                                     url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/" },
  { id: "A06:2021", short: "A06", name: "Vulnerable Components",              desc: "Components with known vulnerabilities may undermine application defenses and enable various attacks from data exposure to full server compromise.",                              url: "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/" },
  { id: "A07:2021", short: "A07", name: "Auth Failures",                      desc: "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks.",                                    url: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/" },
  { id: "A08:2021", short: "A08", name: "Data Integrity Failures",            desc: "Code and infrastructure assumptions about data integrity without verification. CI/CD pipeline risks and insecure deserialization fall here.",                                   url: "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/" },
  { id: "A09:2021", short: "A09", name: "Logging & Monitoring Failures",      desc: "Insufficient logging and monitoring allows attacks to persist undetected, pivot to more systems, and tamper or destroy data.",                                                   url: "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/" },
  { id: "A10:2021", short: "A10", name: "Server-Side Request Forgery",        desc: "SSRF flaws allow attackers to induce the server to make requests to unintended locations, bypassing firewalls, VPNs, and network ACLs.",                                        url: "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery/" },
];

const SCANNER_COVERED = new Set(["A01:2021","A02:2021","A03:2021","A05:2021","A06:2021","A07:2021"]);
const SEV_ORDER = ["critical","high","medium","low","info"] as const;
const SEV_COLOR: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22d3ee", info: "#6b7280",
};
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

// ── Compliance score gauge (SVG arc) ──────────────────────────────────────────

function ScoreGauge({ score }: { score: number | null }) {
  const s = score ?? 0;
  const r = 54;
  const cx = 70; const cy = 70;
  const startAngle = -210;
  const sweepAngle = 240;
  const toRad = (d: number) => (d * Math.PI) / 180;
  const arcPath = (sa: number, sw: number) => {
    const ea = sa + sw;
    const x1 = cx + r * Math.cos(toRad(sa));
    const y1 = cy + r * Math.sin(toRad(sa));
    const x2 = cx + r * Math.cos(toRad(ea));
    const y2 = cy + r * Math.sin(toRad(ea));
    const lg = sw > 180 ? 1 : 0;
    return `M ${x1} ${y1} A ${r} ${r} 0 ${lg} 1 ${x2} ${y2}`;
  };
  const filledSweep = (s / 100) * sweepAngle;
  const color = s >= 80 ? "#22c55e" : s >= 50 ? "#eab308" : "#ef4444";
  return (
    <svg width={140} height={110} viewBox="0 0 140 110">
      <path d={arcPath(startAngle, sweepAngle)} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth={10} strokeLinecap="round" />
      {s > 0 && <path d={arcPath(startAngle, filledSweep)} fill="none" stroke={color} strokeWidth={10} strokeLinecap="round"
        style={{ filter: `drop-shadow(0 0 6px ${color}80)` }} />}
      <text x={cx} y={cy + 4} textAnchor="middle" fontSize={22} fontWeight={700} fill={color} fontFamily="monospace">{score ?? "—"}</text>
      <text x={cx} y={cy + 20} textAnchor="middle" fontSize={9} fill="rgba(255,255,255,0.45)" fontFamily="sans-serif">/ 100</text>
    </svg>
  );
}

// ── Sparkline ─────────────────────────────────────────────────────────────────

function Sparkline({ data, color }: { data: number[]; color: string }) {
  const chartData = data.map((v, i) => ({ i, v }));
  return (
    <ResponsiveContainer width={80} height={28}>
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

// ── Status pill ───────────────────────────────────────────────────────────────

function StatusPill({ status }: { status: "pass" | "fail" | "partial" | "no-data" | "gap" }) {
  const cfg = {
    pass:     { label: "PASS",        icon: <CheckCircle2 className="w-3 h-3" />, bg: "rgba(34,197,94,0.15)",   color: "#22c55e", border: "rgba(34,197,94,0.4)",    glow: "0 0 8px rgba(34,197,94,0.3)" },
    fail:     { label: "FAIL",        icon: <XCircle className="w-3 h-3" />,      bg: "rgba(239,68,68,0.15)",   color: "#ef4444", border: "rgba(239,68,68,0.4)",    glow: "0 0 8px rgba(239,68,68,0.4)" },
    partial:  { label: "PARTIAL",     icon: <AlertCircle className="w-3 h-3" />,  bg: "rgba(234,179,8,0.15)",   color: "#eab308", border: "rgba(234,179,8,0.4)",    glow: "0 0 8px rgba(234,179,8,0.2)" },
    "no-data":{ label: "NO DATA",     icon: <AlertCircle className="w-3 h-3" />,  bg: "rgba(107,114,128,0.15)", color: "#6b7280", border: "rgba(107,114,128,0.3)", glow: "none" },
    gap:      { label: "NO COVERAGE", icon: <Lock className="w-3 h-3" />,         bg: "rgba(107,114,128,0.12)", color: "#94a3b8", border: "rgba(107,114,128,0.3)", glow: "none" },
  };
  const c = cfg[status] ?? cfg["no-data"];
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-bold font-mono"
      style={{ background: c.bg, color: c.color, border: `1px solid ${c.border}`, boxShadow: c.glow }}>
      {c.icon}{c.label}
    </span>
  );
}

// ── Risk ribbon ───────────────────────────────────────────────────────────────

function RiskRibbon({ items, heatmap, onHover, hovered }: {
  items: any[]; heatmap: Record<string,Record<string,number>>;
  onHover: (id: string | null) => void; hovered: string | null;
}) {
  const maxTotal = Math.max(1, ...OWASP_TOP10.map(c => {
    const h = heatmap[c.id] ?? {};
    return Object.values(h).reduce((a, b) => a + b, 0);
  }));
  return (
    <div className="flex items-end gap-1 h-16 px-1">
      {OWASP_TOP10.map((cat) => {
        const item = items.find((o: any) => o.id === cat.id);
        const h = heatmap[cat.id] ?? {};
        const total = Object.values(h).reduce((a, b) => a + b, 0);
        const heightPct = Math.max(8, (total / maxTotal) * 100);
        const passed = item?.status === "pass" || total === 0;
        const gap = !SCANNER_COVERED.has(cat.id);
        const color = gap ? "#eab308" : passed ? "#22c55e" : "#ef4444";
        const isHov = hovered === cat.id;
        return (
          <div key={cat.id} className="flex-1 flex flex-col items-center gap-1 cursor-pointer group"
            onMouseEnter={() => onHover(cat.id)} onMouseLeave={() => onHover(null)}>
            <div className="relative w-full flex flex-col items-center">
              {isHov && (
                <div className="absolute -top-8 left-1/2 -translate-x-1/2 z-10 whitespace-nowrap text-[10px] px-2 py-1 rounded font-mono"
                  style={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", color: "hsl(var(--foreground))" }}>
                  {cat.short}: {total} findings
                </div>
              )}
              <div className="w-full rounded-t-sm transition-all duration-300"
                style={{
                  height: `${heightPct}%`, minHeight: 4,
                  background: color,
                  opacity: isHov ? 1 : 0.7,
                  boxShadow: isHov ? `0 0 8px ${color}80` : "none",
                }} />
            </div>
            <span className="text-[9px] font-mono font-bold transition-colors"
              style={{ color: isHov ? color : "hsl(var(--muted-foreground))" }}>
              {cat.short.replace(":2021","").replace("A0","A")}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// ── Category card (card view) ─────────────────────────────────────────────────

function CategoryCard({ cat, item, sev, rem, spark, onDrill, onExpand, isExpanded }: {
  cat: typeof OWASP_TOP10[0]; item: any; sev: Record<string,number>;
  rem: { total: number; fixed: number }; spark: number[];
  onDrill: () => void; onExpand: () => void; isExpanded: boolean;
}) {
  const total = Object.values(sev).reduce((a, b) => a + b, 0);
  const fixPct = rem.total > 0 ? Math.round((rem.fixed / rem.total) * 100) : 0;
  const passed = item?.status === "pass" || total === 0;
  const isGap = !SCANNER_COVERED.has(cat.id);
  const trend = spark[spark.length - 1] - spark[0];
  const riskScore = Math.min(100, (sev.critical ?? 0) * 20 + (sev.high ?? 0) * 10 + (sev.medium ?? 0) * 5);
  const ringColor = isGap ? "#eab308" : passed ? "#22c55e" : "#ef4444";
  const accentColor = isGap ? "rgba(234,179,8,0.3)" : passed ? "rgba(34,197,94,0.3)" : "rgba(239,68,68,0.3)";
  const ringR = 18; const ringCirc = 2 * Math.PI * ringR;
  const ringFill = ringCirc - (riskScore / 100) * ringCirc;

  const topEndpoints: string[] = [];
  const sevPills = SEV_ORDER.filter(s => (sev[s] ?? 0) > 0);

  return (
    <div className="rounded-xl border transition-all duration-200 cursor-pointer group overflow-hidden"
      style={{ background: "hsl(var(--card))", borderColor: isExpanded ? accentColor : "hsl(var(--border))", boxShadow: isExpanded ? `0 0 0 1px ${accentColor}` : "none" }}
      onClick={onExpand}>
      {/* Top colored accent bar */}
      <div className="h-0.5 w-full" style={{ background: `linear-gradient(90deg, ${ringColor}, transparent)` }} />

      <div className="p-4">
        <div className="flex items-start gap-4">
          {/* Left: badge + donut ring */}
          <div className="flex flex-col items-center gap-1.5 flex-shrink-0">
            <div className="relative w-12 h-12 flex items-center justify-center rounded-lg"
              style={{ background: `${ringColor}18`, border: `1px solid ${ringColor}40` }}>
              <svg width={48} height={48} className="absolute inset-0" style={{ transform: "rotate(-90deg)" }}>
                <circle cx={24} cy={24} r={ringR} fill="none" stroke={`${ringColor}20`} strokeWidth={3} />
                {riskScore > 0 && <circle cx={24} cy={24} r={ringR} fill="none" stroke={ringColor} strokeWidth={3}
                  strokeDasharray={ringCirc} strokeDashoffset={ringFill} strokeLinecap="round"
                  style={{ filter: `drop-shadow(0 0 3px ${ringColor}80)` }} />}
              </svg>
              <span className="text-[11px] font-black font-mono z-10" style={{ color: ringColor }}>{cat.short.replace(":2021","")}</span>
            </div>
            <StatusPill status={isGap ? "gap" : passed ? "pass" : total > 0 ? "fail" : "no-data"} />
          </div>

          {/* Center: info */}
          <div className="flex-1 min-w-0 space-y-2">
            <div>
              <p className="text-sm font-semibold leading-tight">{cat.name}</p>
              {isExpanded && (
                <p className="text-xs text-muted-foreground mt-1 leading-relaxed">{cat.desc}</p>
              )}
            </div>

            {/* Severity pills */}
            <div className="flex flex-wrap gap-1">
              {sevPills.length === 0 ? (
                <span className="text-[10px] text-muted-foreground">No findings</span>
              ) : sevPills.map(s => (
                <span key={s} className="inline-flex items-center gap-0.5 text-[10px] font-bold font-mono px-1.5 py-0.5 rounded"
                  style={{ background: `${SEV_COLOR[s]}20`, color: SEV_COLOR[s], border: `1px solid ${SEV_COLOR[s]}40` }}>
                  {s[0].toUpperCase()}:{sev[s]}
                </span>
              ))}
              {isGap && <span className="text-[10px] px-1.5 py-0.5 rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/30">blind spot</span>}
            </div>

            {/* Fix rate bar */}
            {rem.total > 0 && (
              <div>
                <div className="flex justify-between mb-1">
                  <span className="text-[10px] text-muted-foreground">Fix rate</span>
                  <span className="text-[10px] font-mono" style={{ color: fixPct >= 80 ? "#22c55e" : fixPct >= 40 ? "#eab308" : "#ef4444" }}>
                    {fixPct}% · {rem.fixed}/{rem.total}
                  </span>
                </div>
                <div className="h-1 rounded-full overflow-hidden" style={{ background: "hsl(var(--muted))" }}>
                  <div className="h-full rounded-full transition-all duration-500"
                    style={{ width: `${fixPct}%`, background: fixPct >= 80 ? "#22c55e" : fixPct >= 40 ? "#eab308" : "#ef4444" }} />
                </div>
              </div>
            )}
          </div>

          {/* Right: sparkline + trend */}
          <div className="flex flex-col items-end gap-1 flex-shrink-0">
            <Sparkline data={spark} color={passed ? "#22c55e" : "#ef4444"} />
            <div className="flex items-center gap-1">
              {trend > 0 ? <TrendingUp className="w-3 h-3 text-red-400" /> : trend < 0 ? <TrendingDown className="w-3 h-3 text-green-400" /> : null}
              <span className="text-[10px] font-mono" style={{ color: trend > 0 ? "#ef4444" : trend < 0 ? "#22c55e" : "hsl(var(--muted-foreground))" }}>
                {trend > 0 ? `+${trend}` : trend < 0 ? `${trend}` : "stable"}
              </span>
            </div>
          </div>
        </div>

        {/* Expanded actions */}
        {isExpanded && (
          <div className="mt-4 pt-3 border-t flex items-center justify-between"
            style={{ borderColor: "hsl(var(--border))" }}>
            <div className="flex gap-2">
              <a href={cat.url} target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()}>
                <Button size="sm" variant="outline" className="h-7 text-xs gap-1.5">
                  <ExternalLink className="w-3 h-3" />OWASP Docs
                </Button>
              </a>
              <Button size="sm" variant="outline" className="h-7 text-xs gap-1.5"
                onClick={e => { e.stopPropagation(); onDrill(); }}>
                <Search className="w-3 h-3" />View {total} Findings
              </Button>
            </div>
            <span className="text-[10px] text-muted-foreground font-mono">{cat.id}</span>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Drill-down side panel ─────────────────────────────────────────────────────

function DrillPanel({ category, findings, loading, onClose }: {
  category: typeof OWASP_TOP10[0]; findings: any[]; loading: boolean; onClose: () => void;
}) {
  const [, setLocation] = useLocation();
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const totalFindings = findings.length;
  const openCount = findings.filter(f => f.status === "open" || !f.status).length;
  const fixedCount = findings.filter(f => f.status === "resolved").length;

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div className="h-full w-full max-w-xl border-l shadow-2xl overflow-hidden flex flex-col"
        style={{ background: "hsl(var(--card))", borderColor: "hsl(var(--border))" }}
        onClick={e => e.stopPropagation()}>

        {/* Panel header with gradient banner */}
        <div className="flex-shrink-0">
          <div className="px-5 py-4 relative overflow-hidden"
            style={{ background: "linear-gradient(135deg, rgba(124,58,237,0.2), rgba(168,85,247,0.05))", borderBottom: "1px solid hsl(var(--border))" }}>
            <div className="absolute inset-0 opacity-5"
              style={{ backgroundImage: "repeating-linear-gradient(45deg, transparent, transparent 4px, rgba(124,58,237,0.5) 4px, rgba(124,58,237,0.5) 5px)" }} />
            <div className="relative flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-mono font-bold px-2 py-0.5 rounded"
                    style={{ background: "rgba(124,58,237,0.3)", color: "#a855f7" }}>{category.short}</span>
                  <span className="font-semibold text-sm">{category.name}</span>
                </div>
                <p className="text-xs text-muted-foreground leading-relaxed max-w-sm">{category.desc}</p>
                <div className="flex items-center gap-2 mt-2">
                  <span className="text-xs px-2 py-0.5 rounded-full font-mono" style={{ background: "rgba(239,68,68,0.15)", color: "#ef4444" }}>{openCount} open</span>
                  <span className="text-xs px-2 py-0.5 rounded-full font-mono" style={{ background: "rgba(34,197,94,0.15)", color: "#22c55e" }}>{fixedCount} fixed</span>
                  <span className="text-xs px-2 py-0.5 rounded-full font-mono" style={{ background: "hsl(var(--muted))", color: "hsl(var(--muted-foreground))" }}>{totalFindings} total</span>
                </div>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <a href={category.url} target="_blank" rel="noopener noreferrer"
                  className="p-1.5 rounded hover:bg-accent/50 text-muted-foreground hover:text-foreground transition-colors">
                  <ExternalLink className="w-4 h-4" />
                </a>
                <button onClick={onClose}
                  className="p-1.5 rounded hover:bg-accent/50 text-muted-foreground hover:text-foreground transition-colors">
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Findings list */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          {loading ? (
            [...Array(5)].map((_, i) => (
              <div key={i} className="h-16 rounded-lg animate-pulse" style={{ background: "hsl(var(--muted))" }} />
            ))
          ) : findings.length === 0 ? (
            <div className="py-16 text-center">
              <ShieldCheck className="w-10 h-10 mx-auto text-green-400 mb-3" />
              <p className="text-sm font-medium text-green-400">No findings for this category</p>
              <p className="text-xs text-muted-foreground mt-1">This category is currently clean.</p>
            </div>
          ) : (
            findings.map(f => {
              const isExp = expandedFinding === f.id;
              const sColor = SEV_COLOR[f.severity] ?? "#6b7280";
              return (
                <div key={f.id}
                  className="rounded-lg border transition-all duration-200 overflow-hidden"
                  style={{
                    borderColor: isExp ? `${sColor}50` : "hsl(var(--border))",
                    borderLeft: `3px solid ${sColor}`,
                    background: isExp ? `${sColor}08` : "transparent",
                  }}>
                  <div className="p-3 cursor-pointer flex items-start gap-3"
                    onClick={() => setExpandedFinding(isExp ? null : f.id)}>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                        <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded"
                          style={{ background: `${sColor}20`, color: sColor }}>{f.severity}</span>
                        <span className="text-sm font-medium truncate">{f.title}</span>
                      </div>
                      <p className="text-[11px] font-mono text-muted-foreground truncate">{f.endpoint}</p>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      {f.cvss_score && (
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border"
                          style={{ color: sColor, borderColor: `${sColor}40`, background: `${sColor}10` }}>
                          {f.cvss_score}
                        </span>
                      )}
                      <ChevronDown className={`w-3.5 h-3.5 text-muted-foreground transition-transform ${isExp ? "rotate-180" : ""}`} />
                    </div>
                  </div>
                  {isExp && (
                    <div className="px-3 pb-3 space-y-2 border-t" style={{ borderColor: `${sColor}20` }}>
                      <div className="flex items-center gap-2 pt-2 flex-wrap">
                        <span className="text-[10px] px-2 py-0.5 rounded font-mono capitalize"
                          style={{ background: "hsl(var(--muted))", color: "hsl(var(--muted-foreground))" }}>
                          {(f.validation_status ?? "open").replace("_", " ")}
                        </span>
                        {f.cwe_id && <span className="text-[10px] text-muted-foreground font-mono">CWE-{f.cwe_id}</span>}
                      </div>
                      {f.description && <p className="text-xs text-muted-foreground leading-relaxed">{String(f.description).slice(0, 200)}{f.description.length > 200 ? "…" : ""}</p>}
                      <div className="flex gap-2 pt-1">
                        <Button size="sm" variant="outline" className="h-7 text-xs gap-1.5 flex-1"
                          onClick={() => setLocation(`/findings/${f.id}`)}>
                          <ArrowUpRight className="w-3 h-3" />Go to Finding
                        </Button>
                        <Button size="sm" variant="outline" className="h-7 text-xs gap-1.5 flex-1"
                          onClick={() => setLocation(`/remediations?finding=${f.id}`)}>
                          <Sparkles className="w-3 h-3" />Remediate
                        </Button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>

        {/* Sticky bottom bar */}
        <div className="flex-shrink-0 border-t px-4 py-3 flex items-center gap-2"
          style={{ borderColor: "hsl(var(--border))", background: "hsl(var(--card))" }}>
          <Button size="sm" className="flex-1 h-8 text-xs gap-1.5"
            style={{ background: "linear-gradient(135deg, #7c3aed, #a855f7)", color: "white", border: "none" }}
            onClick={() => setLocation(`/findings?owasp=${category.id}`)}>
            <Search className="w-3.5 h-3.5" />View All {totalFindings} Findings
          </Button>
          <Button size="sm" variant="outline" className="h-8 text-xs gap-1.5"
            onClick={() => setLocation("/ai-triage")}>
            <Sparkles className="w-3.5 h-3.5" />AI Remediation Plan
          </Button>
        </div>
      </div>
    </div>
  );
}

// ── Heatmap table row ─────────────────────────────────────────────────────────

function HeatmapRow({ cat, item, sev, rem, spark, maxCell, expanded, onExpand, onDrill }: {
  cat: typeof OWASP_TOP10[0]; item: any; sev: Record<string,number>;
  rem: { total: number; fixed: number }; spark: number[];
  maxCell: number; expanded: boolean; onExpand: () => void; onDrill: (sevFilter?: string) => void;
}) {
  const total = Object.values(sev).reduce((a, b) => a + b, 0);
  const fixPct = rem.total > 0 ? Math.round((rem.fixed / rem.total) * 100) : 0;
  const trend = spark[spark.length - 1] - spark[0];
  const passed = item?.status === "pass" || total === 0;
  const isGap = !SCANNER_COVERED.has(cat.id);

  return (
    <>
      <tr className="transition-colors border-t cursor-pointer group/row"
        style={{ borderColor: "hsl(var(--border))" }}
        onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = "hsl(var(--muted)/0.5)"}
        onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = ""}
        onClick={onExpand}>
        <td className="py-2.5 pr-3 pl-2">
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-mono font-bold w-8 text-center px-1 py-0.5 rounded"
              style={{ background: passed && !isGap ? "rgba(34,197,94,0.15)" : isGap ? "rgba(234,179,8,0.15)" : "rgba(239,68,68,0.15)",
                       color: passed && !isGap ? "#22c55e" : isGap ? "#eab308" : "#ef4444" }}>
              {cat.short.replace(":2021","").replace("A0","A")}
            </span>
            <span className="text-sm truncate max-w-[160px]" title={cat.name}>{cat.name}</span>
            {isGap && <span className="text-[9px] px-1 py-0.5 rounded bg-yellow-500/15 text-yellow-400 border border-yellow-500/25 hidden sm:inline">gap</span>}
          </div>
        </td>
        {SEV_ORDER.map(s => {
          const n = sev[s] ?? 0;
          const intensity = maxCell > 0 ? n / maxCell : 0;
          const bg = n > 0 ? `${SEV_COLOR[s]}${Math.round(20 + intensity * 55).toString(16).padStart(2,"0")}` : "transparent";
          return (
            <td key={s} className="py-2.5 px-1 text-center">
              <button
                className="mx-auto w-9 h-8 rounded-md flex items-center justify-center text-xs font-bold transition-all hover:scale-110"
                style={{ background: bg, color: n > 0 ? SEV_COLOR[s] : "hsl(var(--muted-foreground))", border: n > 0 ? `1px solid ${SEV_COLOR[s]}40` : "1px solid transparent" }}
                title={n > 0 ? `${n} ${s} finding${n !== 1 ? "s" : ""} — click to view` : `No ${s} findings`}
                onClick={e => { e.stopPropagation(); if (n > 0) onDrill(s); }}>
                {n > 0 ? n : "·"}
              </button>
            </td>
          );
        })}
        <td className="py-2.5 px-2">
          <div className="flex items-center gap-1">
            <Sparkline data={spark} color={passed ? "#22c55e" : "#ef4444"} />
            {trend > 0 ? <TrendingUp className="w-3 h-3 text-red-400" /> : trend < 0 ? <TrendingDown className="w-3 h-3 text-green-400" /> : null}
          </div>
        </td>
        <td className="py-2.5 px-2">
          {rem.total > 0 ? (
            <div className="w-20">
              <div className="flex justify-between mb-1">
                <span className="text-[10px] text-muted-foreground">{fixPct}%</span>
                <span className="text-[10px] text-muted-foreground">{rem.fixed}/{rem.total}</span>
              </div>
              <div className="h-1.5 rounded-full overflow-hidden" style={{ background: "hsl(var(--muted))" }}>
                <div className="h-full rounded-full"
                  style={{ width: `${fixPct}%`, background: fixPct >= 80 ? "#22c55e" : fixPct >= 40 ? "#eab308" : "#ef4444" }} />
              </div>
            </div>
          ) : <span className="text-muted-foreground text-xs">—</span>}
        </td>
        <td className="py-2.5 px-2">
          <StatusPill status={isGap ? "gap" : passed ? "pass" : total > 0 ? "fail" : "no-data"} />
        </td>
        <td className="py-2.5 px-2">
          <div className="flex items-center gap-1 opacity-0 group-hover/row:opacity-100 transition-opacity">
            <button title="View findings"
              className="p-1 rounded hover:bg-accent text-muted-foreground hover:text-primary transition-colors"
              onClick={e => { e.stopPropagation(); onDrill(); }}>
              <Search className="w-3.5 h-3.5" />
            </button>
            {expanded ? <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" /> : <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" />}
          </div>
        </td>
      </tr>
      {expanded && (
        <tr style={{ background: "hsl(var(--muted)/0.3)" }}>
          <td colSpan={10} className="px-4 py-4">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div>
                <p className="text-[10px] text-muted-foreground font-semibold uppercase tracking-wider mb-1.5">About</p>
                <p className="text-xs text-muted-foreground leading-relaxed">{cat.desc}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground font-semibold uppercase tracking-wider mb-1.5">Severity Breakdown</p>
                <div className="flex flex-col gap-1">
                  {SEV_ORDER.filter(s => (sev[s] ?? 0) > 0).map(s => (
                    <div key={s} className="flex items-center gap-2">
                      <span className="text-[10px] font-mono capitalize w-16" style={{ color: SEV_COLOR[s] }}>{s}</span>
                      <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: "hsl(var(--muted))" }}>
                        <div className="h-full rounded-full" style={{ width: `${((sev[s] ?? 0) / (total || 1)) * 100}%`, background: SEV_COLOR[s] }} />
                      </div>
                      <span className="text-[10px] font-mono text-muted-foreground w-4">{sev[s]}</span>
                    </div>
                  ))}
                  {total === 0 && <span className="text-xs text-muted-foreground">No findings in this category.</span>}
                </div>
              </div>
              <div className="flex flex-col gap-2">
                <p className="text-[10px] text-muted-foreground font-semibold uppercase tracking-wider">Actions</p>
                <a href={cat.url} target="_blank" rel="noopener noreferrer">
                  <Button size="sm" variant="outline" className="h-7 text-xs gap-1.5 w-full">
                    <ExternalLink className="w-3 h-3" />OWASP Documentation
                  </Button>
                </a>
                <Button size="sm" variant="outline" className="h-7 text-xs gap-1.5 w-full"
                  onClick={() => onDrill()}>
                  <Search className="w-3 h-3" />View All {total} Findings
                </Button>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ── Skeleton ──────────────────────────────────────────────────────────────────

function Skeleton({ className }: { className?: string }) {
  return <div className={`animate-pulse rounded-md bg-muted/50 ${className ?? ""}`} />;
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function OWASPPage() {
  const [expanded, setExpanded] = useState<string | null>(null);
  const [drillId, setDrillId] = useState<string | null>(null);
  const [drillFindings, setDrillFindings] = useState<any[]>([]);
  const [drillLoading, setDrillLoading] = useState(false);
  const [view, setView] = useState<"cards" | "table">("cards");
  const [filter, setFilter] = useState<"all" | "failed" | "findings" | "gaps">("all");
  const [ribbonHovered, setRibbonHovered] = useState<string | null>(null);
  const [gapDismissed, setGapDismissed] = useState(false);
  const [lastUpdated] = useState(new Date());

  const { data: report, isLoading: reportLoading } = useQuery<any>({
    queryKey: ["/api/compliance/report"],
    queryFn: () => fetch("/api/compliance/report", { credentials: "include" }).then(r => r.json()),
  });

  const { data: allFindings = [], isLoading: findingsLoading } = useQuery<any[]>({
    queryKey: ["/api/findings", "owasp"],
    queryFn: () => fetch("/api/findings?limit=500", { credentials: "include" }).then(r => r.json()).then(d => Array.isArray(d) ? d : d?.items ?? []),
  });

  const { data: remediations = [] } = useQuery<any[]>({
    queryKey: ["/api/remediations"],
    queryFn: () => fetch("/api/remediations?limit=200", { credentials: "include" }).then(r => r.json()).then(d => Array.isArray(d) ? d : d?.items ?? []),
  });

  const isLoading = reportLoading || findingsLoading;

  const sparklineData = useMemo(() => {
    const now = Date.now();
    const result: Record<string, number[]> = {};
    for (const cat of OWASP_TOP10) {
      const weeks: number[] = [];
      for (let i = 7; i >= 0; i--) {
        const wStart = new Date(now - (i + 1) * 7 * 24 * 60 * 60 * 1000);
        const wEnd = new Date(now - i * 7 * 24 * 60 * 60 * 1000);
        const count = allFindings.filter(f => { const d = new Date(f.created_at); return d >= wStart && d < wEnd; }).length;
        weeks.push(count);
      }
      result[cat.id] = weeks;
    }
    return result;
  }, [allFindings]);

  const heatmapData = useMemo(() => {
    const result: Record<string, Record<string, number>> = {};
    for (const cat of OWASP_TOP10) {
      const cats = REVERSE_MAP[cat.id] ?? [];
      const catFindings = allFindings.filter(f => cats.includes(f.category ?? ""));
      result[cat.id] = {};
      for (const sev of SEV_ORDER) result[cat.id][sev] = catFindings.filter(f => f.severity === sev).length;
    }
    return result;
  }, [allFindings]);

  const remediationRate = useMemo(() => {
    const result: Record<string, { total: number; fixed: number }> = {};
    const resolvedIds = new Set(remediations.filter(r => r.status === "resolved").map(r => r.finding_id).filter(Boolean));
    for (const cat of OWASP_TOP10) {
      const cats = REVERSE_MAP[cat.id] ?? [];
      const catFindings = allFindings.filter(f => cats.includes(f.category ?? ""));
      result[cat.id] = { total: catFindings.length, fixed: catFindings.filter(f => resolvedIds.has(f.id)).length };
    }
    return result;
  }, [allFindings, remediations]);

  const benchmarkScore = useMemo(() => {
    const WEIGHTS = { critical: 20, high: 10, medium: 5, low: 2, info: 0 };
    let penalty = 0;
    for (const cat of OWASP_TOP10) {
      const h = heatmapData[cat.id] ?? {};
      for (const [s, w] of Object.entries(WEIGHTS)) penalty += (h[s] ?? 0) * w;
    }
    return Math.max(0, Math.min(100, 100 - Math.round(penalty / 2)));
  }, [heatmapData]);

  const owaspItems = report?.owasp_top10 ?? OWASP_TOP10.map(c => ({ ...c, status: "pass", findings_count: 0 }));
  const failCount = owaspItems.filter((o: any) => o.status === "fail").length;
  const coverageGaps = OWASP_TOP10.filter(c => !SCANNER_COVERED.has(c.id));
  const totalOpenFindings = allFindings.filter(f => !f.status || f.status === "open").length;
  const resolvedIds = new Set(remediations.filter(r => r.status === "resolved").map(r => r.finding_id).filter(Boolean));
  const totalFixed = allFindings.filter(f => resolvedIds.has(f.id)).length;
  const overallFixPct = allFindings.length > 0 ? Math.round((totalFixed / allFindings.length) * 100) : 0;

  const maxCell = useMemo(() => {
    let m = 1;
    for (const v of Object.values(heatmapData)) for (const n of Object.values(v)) if (n > m) m = n;
    return m;
  }, [heatmapData]);

  async function openDrill(catId: string, sevFilter?: string) {
    setDrillId(catId);
    setDrillLoading(true);
    try {
      const res = await fetch(`/api/compliance/owasp/findings/${catId}`, { credentials: "include" });
      let data = await res.json();
      if (!Array.isArray(data)) data = data?.items ?? [];
      if (sevFilter) data = data.filter((f: any) => f.severity === sevFilter);
      setDrillFindings(data);
    } catch { setDrillFindings([]); }
    setDrillLoading(false);
  }

  const drillCat = OWASP_TOP10.find(c => c.id === drillId);

  const filteredCategories = OWASP_TOP10.filter(cat => {
    const item = owaspItems.find((o: any) => o.id === cat.id);
    const h = heatmapData[cat.id] ?? {};
    const total = Object.values(h).reduce((a, b) => a + b, 0);
    if (filter === "failed") return item?.status === "fail" || total > 0;
    if (filter === "findings") return total > 0;
    if (filter === "gaps") return !SCANNER_COVERED.has(cat.id);
    return true;
  });

  const scoreColor = benchmarkScore >= 80 ? "#22c55e" : benchmarkScore >= 50 ? "#eab308" : "#ef4444";

  return (
    <div className="space-y-0 -m-6">

      {/* ── 1. HERO HEADER ─────────────────────────────────────────────────── */}
      <div className="relative overflow-hidden px-6 pt-6 pb-5"
        style={{ background: "linear-gradient(135deg, hsl(var(--sidebar)) 0%, hsl(var(--background)) 100%)", borderBottom: "1px solid hsl(var(--border))" }}>
        {/* Background grid pattern */}
        <div className="absolute inset-0 opacity-[0.03]"
          style={{ backgroundImage: "linear-gradient(hsl(var(--foreground)) 1px,transparent 1px),linear-gradient(90deg,hsl(var(--foreground)) 1px,transparent 1px)", backgroundSize: "40px 40px" }} />

        <div className="relative flex flex-col lg:flex-row lg:items-center gap-6">
          {/* Title + desc */}
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-1">
              <div className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0"
                style={{ background: "linear-gradient(135deg, #7c3aed, #a855f7)" }}>
                <ShieldCheck className="w-5 h-5 text-white" />
              </div>
              <h1 className="text-2xl font-bold tracking-tight">OWASP Top 10 — 2021</h1>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded border"
                style={{ background: "rgba(124,58,237,0.15)", color: "#a855f7", borderColor: "rgba(124,58,237,0.3)" }}>
                ENTERPRISE
              </span>
            </div>
            <p className="text-sm text-muted-foreground">
              Real-time compliance posture, coverage heatmap, trend analytics and remediation tracking.
            </p>

            {/* Status strip */}
            <div className="flex flex-wrap items-center gap-x-5 gap-y-2 mt-4">
              {[
                { label: "Passed", value: isLoading ? "—" : `${10 - failCount}/10`, color: "#22c55e", icon: <CheckCircle2 className="w-3.5 h-3.5" /> },
                { label: "Failed", value: isLoading ? "—" : `${failCount}/10`,       color: "#ef4444", icon: <XCircle className="w-3.5 h-3.5" /> },
                { label: "Coverage Gaps", value: isLoading ? "—" : `${coverageGaps.length}`, color: "#eab308", icon: <Lock className="w-3.5 h-3.5" /> },
                { label: "Open Findings", value: isLoading ? "—" : `${totalOpenFindings}`, color: "#f97316", icon: <AlertTriangle className="w-3.5 h-3.5" /> },
                { label: "Fix Rate",      value: isLoading ? "—" : `${overallFixPct}%`, color: "#22d3ee", icon: <Activity className="w-3.5 h-3.5" /> },
              ].map(s => (
                <div key={s.label} className="flex items-center gap-1.5">
                  <span style={{ color: s.color }}>{s.icon}</span>
                  <span className="text-sm font-bold" style={{ color: s.color }}>{s.value}</span>
                  <span className="text-xs text-muted-foreground">{s.label}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Score gauge */}
          <div className="flex flex-col items-center gap-1 flex-shrink-0">
            {isLoading ? (
              <div className="w-[140px] h-[110px] rounded-xl animate-pulse" style={{ background: "hsl(var(--muted))" }} />
            ) : (
              <ScoreGauge score={benchmarkScore} />
            )}
            <p className="text-xs text-muted-foreground">Compliance Score</p>
            <div className="flex items-center gap-1.5 text-[10px] font-mono">
              <span className="text-muted-foreground">Industry avg:</span>
              <span style={{ color: "#6b7280" }}>74</span>
              <span style={{ color: scoreColor }}>{benchmarkScore >= 74 ? `↑ +${benchmarkScore - 74}` : `↓ ${benchmarkScore - 74}`}</span>
            </div>
          </div>
        </div>

        {/* Animated risk bar at bottom */}
        <div className="absolute bottom-0 left-0 right-0 h-0.5"
          style={{ background: `linear-gradient(90deg, transparent 0%, #ef4444 ${100 - benchmarkScore}%, #eab308 60%, #22c55e ${benchmarkScore}%, transparent 100%)`, opacity: 0.7 }} />
      </div>

      <div className="px-6 py-6 space-y-5">

        {/* ── 9. STICKY TOOLBAR ──────────────────────────────────────────────── */}
        <div className="flex flex-wrap items-center gap-3 p-3 rounded-xl sticky top-0 z-20"
          style={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", backdropFilter: "blur(12px)" }}>
          {/* View toggle */}
          <div className="flex items-center gap-0.5 p-0.5 rounded-lg" style={{ background: "hsl(var(--muted))" }}>
            {([["cards", <LayoutGrid className="w-3.5 h-3.5" />,"Cards"], ["table", <Table2 className="w-3.5 h-3.5" />,"Table"]] as [string, React.ReactNode, string][]).map(([v, icon, label]) => (
              <button key={v} onClick={() => setView(v as any)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all"
                style={view === v
                  ? { background: "hsl(var(--card))", color: "hsl(var(--foreground))", boxShadow: "0 1px 3px rgba(0,0,0,0.2)" }
                  : { color: "hsl(var(--muted-foreground))" }}>
                {icon}{label}
              </button>
            ))}
          </div>

          {/* Filter chips */}
          <div className="flex items-center gap-1 flex-1 flex-wrap">
            <Filter className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
            {([["all","All 10"], ["failed","Failed Only"], ["findings","Has Findings"], ["gaps","Coverage Gaps"]] as [string,string][]).map(([v, label]) => (
              <button key={v} onClick={() => setFilter(v as any)}
                className="text-[11px] font-medium px-2.5 py-1 rounded-full transition-all"
                style={filter === v
                  ? { background: "hsl(var(--primary))", color: "white" }
                  : { background: "hsl(var(--muted))", color: "hsl(var(--muted-foreground))" }}>
                {label}
              </button>
            ))}
          </div>

          {/* Right: timestamp + export */}
          <div className="flex items-center gap-2 flex-shrink-0">
            <span className="text-[10px] text-muted-foreground flex items-center gap-1 hidden sm:flex">
              <Clock className="w-3 h-3" />Updated {lastUpdated.toLocaleTimeString()}
            </span>
            <Button size="sm" variant="outline" className="h-7 text-xs gap-1.5">
              <Download className="w-3.5 h-3.5" />Export PDF
            </Button>
            <Button size="sm" variant="outline" className="h-7 w-7 p-0">
              <RefreshCw className="w-3.5 h-3.5" />
            </Button>
          </div>
        </div>

        {/* ── 3. RISK RIBBON ─────────────────────────────────────────────────── */}
        <div className="rounded-xl p-4" style={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))" }}>
          <div className="flex items-center justify-between mb-3">
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Risk Ribbon — Finding Density by Category</p>
            <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm inline-block bg-green-500" />Pass</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm inline-block bg-red-500" />Fail</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm inline-block bg-yellow-500" />Gap</span>
            </div>
          </div>
          {isLoading ? (
            <div className="h-16 rounded animate-pulse" style={{ background: "hsl(var(--muted))" }} />
          ) : (
            <RiskRibbon items={owaspItems} heatmap={heatmapData} onHover={setRibbonHovered} hovered={ribbonHovered} />
          )}
        </div>

        {/* ── 7. COVERAGE GAP BANNER ─────────────────────────────────────────── */}
        {coverageGaps.length > 0 && !gapDismissed && (
          <div className="rounded-xl p-4 relative overflow-hidden"
            style={{ background: "rgba(234,179,8,0.06)", border: "1px solid rgba(234,179,8,0.3)" }}>
            {/* Striped warning left border */}
            <div className="absolute left-0 top-0 bottom-0 w-1.5 rounded-l-xl"
              style={{ background: "repeating-linear-gradient(45deg, #eab308, #eab308 4px, rgba(234,179,8,0.3) 4px, rgba(234,179,8,0.3) 8px)" }} />
            <div className="pl-3">
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-yellow-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className="text-sm font-bold text-yellow-500">SCANNER BLIND SPOTS DETECTED</span>
                    <p className="text-xs text-muted-foreground mt-0.5">
                      {coverageGaps.length} OWASP categories are not actively tested. A clean result here does <strong>not</strong> mean you are safe.
                    </p>
                  </div>
                </div>
                <button onClick={() => setGapDismissed(true)}
                  className="p-1 rounded text-muted-foreground hover:text-foreground hover:bg-accent transition-colors flex-shrink-0">
                  <X className="w-4 h-4" />
                </button>
              </div>
              <div className="flex flex-wrap gap-2 mt-3">
                {coverageGaps.map(c => (
                  <span key={c.id} className="inline-flex items-center gap-1.5 text-xs font-mono px-2.5 py-1 rounded-lg"
                    style={{ background: "rgba(234,179,8,0.12)", border: "1px solid rgba(234,179,8,0.3)", color: "#eab308" }}>
                    <Lock className="w-3 h-3" />{c.short} — {c.name}
                    <span className="text-[9px] px-1 py-0.5 rounded bg-yellow-500/20 text-yellow-300">NOT TESTED</span>
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── 10. LOADING SKELETONS ──────────────────────────────────────────── */}
        {isLoading && (
          <div className={view === "cards" ? "grid grid-cols-1 md:grid-cols-2 gap-4" : "space-y-2"}>
            {[...Array(10)].map((_, i) => (
              <div key={i} className="rounded-xl p-4 space-y-3" style={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))" }}>
                <div className="flex items-start gap-4">
                  <Skeleton className="w-12 h-12 rounded-lg flex-shrink-0" />
                  <div className="flex-1 space-y-2">
                    <Skeleton className="h-4 w-40" />
                    <Skeleton className="h-3 w-full" />
                    <Skeleton className="h-3 w-3/4" />
                    <div className="flex gap-1">
                      <Skeleton className="h-5 w-12 rounded-md" />
                      <Skeleton className="h-5 w-12 rounded-md" />
                      <Skeleton className="h-5 w-12 rounded-md" />
                    </div>
                  </div>
                  <Skeleton className="w-20 h-7 flex-shrink-0" />
                </div>
              </div>
            ))}
          </div>
        )}

        {/* ── 2. CATEGORY CARDS VIEW ─────────────────────────────────────────── */}
        {!isLoading && view === "cards" && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filteredCategories.length === 0 ? (
              <div className="col-span-2 py-16 text-center">
                <Filter className="w-10 h-10 mx-auto text-muted-foreground mb-3" />
                <p className="text-sm font-medium">No categories match this filter</p>
                <Button size="sm" variant="outline" className="mt-3" onClick={() => setFilter("all")}>Show All</Button>
              </div>
            ) : filteredCategories.map(cat => (
              <CategoryCard
                key={cat.id} cat={cat}
                item={owaspItems.find((o: any) => o.id === cat.id)}
                sev={heatmapData[cat.id] ?? {}}
                rem={remediationRate[cat.id] ?? { total: 0, fixed: 0 }}
                spark={sparklineData[cat.id] ?? [0,0,0,0,0,0,0,0]}
                onDrill={() => openDrill(cat.id)}
                onExpand={() => setExpanded(expanded === cat.id ? null : cat.id)}
                isExpanded={expanded === cat.id}
              />
            ))}
          </div>
        )}

        {/* ── 5. HEATMAP TABLE VIEW ──────────────────────────────────────────── */}
        {!isLoading && view === "table" && (
          <div className="rounded-xl overflow-hidden" style={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))" }}>
            <div className="px-4 py-3 border-b flex items-center justify-between" style={{ borderColor: "hsl(var(--border))" }}>
              <div>
                <p className="text-sm font-semibold">Coverage Heatmap</p>
                <p className="text-xs text-muted-foreground">Finding density per category × severity. Click any cell to view those findings.</p>
              </div>
              {/* Heatmap legend */}
              <div className="hidden sm:flex items-center gap-2 text-[10px] text-muted-foreground">
                <span>Intensity:</span>
                {[0.2, 0.4, 0.6, 0.8, 1].map(o => (
                  <div key={o} className="w-4 h-4 rounded-sm" style={{ background: `rgba(239,68,68,${o})` }} />
                ))}
                <span>low → high</span>
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr style={{ background: "hsl(var(--sidebar))", borderBottom: "1px solid hsl(var(--border))" }}>
                    <th className="text-left py-2.5 px-2 text-muted-foreground font-semibold uppercase tracking-wider text-[10px] w-52">Category</th>
                    {SEV_ORDER.map(s => (
                      <th key={s} className="py-2.5 px-1 text-center font-bold text-[10px] uppercase tracking-wider" style={{ color: SEV_COLOR[s] }}>
                        {s.slice(0,4)}
                      </th>
                    ))}
                    <th className="py-2.5 px-2 text-center text-muted-foreground font-semibold uppercase tracking-wider text-[10px]">8wk Trend</th>
                    <th className="py-2.5 px-2 text-center text-muted-foreground font-semibold uppercase tracking-wider text-[10px]">Fix Rate</th>
                    <th className="py-2.5 px-2 text-center text-muted-foreground font-semibold uppercase tracking-wider text-[10px]">Status</th>
                    <th className="py-2.5 px-2 w-12" />
                  </tr>
                </thead>
                <tbody>
                  {filteredCategories.map(cat => (
                    <HeatmapRow
                      key={cat.id} cat={cat}
                      item={owaspItems.find((o: any) => o.id === cat.id)}
                      sev={heatmapData[cat.id] ?? {}}
                      rem={remediationRate[cat.id] ?? { total: 0, fixed: 0 }}
                      spark={sparklineData[cat.id] ?? [0,0,0,0,0,0,0,0]}
                      maxCell={maxCell}
                      expanded={expanded === cat.id}
                      onExpand={() => setExpanded(expanded === cat.id ? null : cat.id)}
                      onDrill={(sev) => openDrill(cat.id, sev)}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Footer note */}
        <p className="text-[11px] text-center text-muted-foreground pb-2">
          Based on {allFindings.length} total findings · Scanner covers {SCANNER_COVERED.size}/10 OWASP categories · Zero findings in an uncovered category does not indicate compliance
        </p>
      </div>

      {/* ── 4. DRILL-DOWN PANEL ─────────────────────────────────────────────── */}
      {drillId && drillCat && (
        <DrillPanel
          category={drillCat}
          findings={drillFindings}
          loading={drillLoading}
          onClose={() => setDrillId(null)}
        />
      )}
    </div>
  );
}
