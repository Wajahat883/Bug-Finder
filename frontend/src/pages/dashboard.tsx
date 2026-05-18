import { useLocation } from "wouter";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, useEffect } from "react";
import { format } from "date-fns";
import {
  useGetDashboardStats,
  useGetDashboardActivity,
  useListScanJobs,
} from "@/api-client";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  LineChart, Line, Legend, ReferenceLine,
} from "recharts";
import { Plus, Activity, TrendingUp } from "lucide-react";
import { Button } from "@/components/ui/button";

/* ─── Sparkline ──────────────────────────────────────────────── */
function Sparkline({ data, color }: { data: number[]; color: string }) {
  const h = 36, w = 80;
  const max = Math.max(...data, 1);
  const min = Math.min(...data);
  const range = max - min || 1;
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * w;
    const y = h - ((v - min) / range) * (h - 4) - 2;
    return `${x},${y}`;
  });
  return (
    <svg width={w} height={h} className="opacity-70">
      <polyline
        points={pts.join(" ")}
        fill="none"
        stroke={color}
        strokeWidth="1.8"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  );
}

/* ─── KPI Card ───────────────────────────────────────────────── */
interface KpiCardProps {
  label: string;
  value: string | number;
  sublabel?: string;
  valueColor: string;
  sparkData: number[];
  sparkColor: string;
  onClick?: () => void;
}
function KpiCard({ label, value, sublabel, valueColor, sparkData, sparkColor, onClick }: KpiCardProps) {
  return (
    <div
      className="rounded-lg p-4 flex flex-col gap-2 border transition-all"
      style={{
        background: "hsl(var(--card))",
        borderColor: "hsl(var(--border))",
        cursor: onClick ? "pointer" : "default",
      }}
      onClick={onClick}
      role={onClick ? "button" : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={onClick ? (e) => { if (e.key === "Enter" || e.key === " ") onClick(); } : undefined}
    >
      <div className="flex items-start justify-between">
        <span className="text-xs font-medium" style={{ color: "hsl(var(--muted-foreground))" }}>
          {label}
        </span>
        <Sparkline data={sparkData} color={sparkColor} />
      </div>
      <div className="flex items-end gap-2">
        <span className="text-3xl font-bold font-mono leading-none" style={{ color: valueColor }}>
          {value}
        </span>
        {sublabel && (
          <span className="text-xs mb-0.5" style={{ color: "hsl(var(--muted-foreground))" }}>
            {sublabel}
          </span>
        )}
      </div>
    </div>
  );
}

/* ─── Activity type label colors ────────────────────────────── */
function activityTag(type: string): { label: string; color: string } {
  const map: Record<string, { label: string; color: string }> = {
    scan_started:        { label: "job_created",      color: "#818cf8" },
    scan_completed:      { label: "phase_completed",  color: "#a78bfa" },
    scan_failed:         { label: "error",            color: "#f87171" },
    finding_discovered:  { label: "finding_detected", color: "#fb923c" },
    target_added:        { label: "info",             color: "#38bdf8" },
    remediation_created: { label: "remediation",      color: "#34d399" },
  };
  return map[type] ?? { label: type, color: "#94a3b8" };
}

/* ─── Generate 7-day throughput data from scan list ─────────── */
function buildThroughputData(scans: any[]): { date: string; scans: number; findings: number }[] {
  const days: Record<string, { scans: number; findings: number }> = {};
  const now = new Date();
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    days[key] = { scans: 0, findings: 0 };
  }
  for (const s of scans) {
    const key = new Date(s.created_at).toISOString().slice(0, 10);
    if (key in days) {
      days[key].scans++;
      days[key].findings += s.findings_count || 0;
    }
  }
  return Object.entries(days).map(([date, v]) => ({ date, ...v }));
}

/* ─── Risk Trend Chart ───────────────────────────────────────── */
function RiskTrendChart() {
  const { data } = useQuery<any[]>({
    queryKey: ["/api/analytics/risk-trend"],
    queryFn: () => fetch("/api/analytics/risk-trend", { credentials: "include" }).then(r => r.json()),
    staleTime: 60000,
  });
  const rows: any[] = Array.isArray(data) ? data : [];
  return (
    <div
      className="rounded-lg border p-4 flex flex-col"
      style={{ background: "hsl(var(--card))", borderColor: "hsl(var(--border))" }}
    >
      <div className="flex items-center gap-2 mb-4">
        <TrendingUp className="w-4 h-4" style={{ color: "hsl(var(--primary))" }} />
        <span className="text-sm font-medium">Risk Trend (12 Weeks)</span>
      </div>
      <div style={{ height: 180 }}>
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={rows} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
            <XAxis dataKey="week" tick={{ fontSize: 9, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fontSize: 9, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} domain={[0, 100]} />
            <Tooltip
              contentStyle={{ background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: 6, fontSize: 11 }}
              labelStyle={{ color: "hsl(var(--foreground))" }}
            />
            <Legend wrapperStyle={{ fontSize: 10 }} />
            <Line type="monotone" dataKey="score" stroke="#c084fc" strokeWidth={2} dot={false} name="Risk Score" />
            <Line type="monotone" dataKey="critical" stroke="#f87171" strokeWidth={1.5} dot={false} name="Critical" />
            <Line type="monotone" dataKey="high" stroke="#fb923c" strokeWidth={1.5} dot={false} name="High" />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

/* ─── Dashboard ──────────────────────────────────────────────── */
export default function Dashboard() {
  const { data: stats } = useGetDashboardStats({ query: { refetchInterval: 10000 } });
  const { data: activity } = useGetDashboardActivity(undefined, { query: { refetchInterval: 10000 } });
  const { data: scansResp } = useListScanJobs({ page_size: 50 });
  const [, setLocation] = useLocation();

  const [isLive, setIsLive] = useState(false);
  const queryClient = useQueryClient();

  useEffect(() => {
    const es = new EventSource("/api/stream/dashboard", { withCredentials: true } as EventSourceInit);
    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as Record<string, unknown>;
        setIsLive(true);
        if (data["type"] === "stats_update") {
          queryClient.setQueryData(["/api/dashboard/stats"], data["stats"]);
        }
        if (data["type"] === "new_finding" || data["type"] === "scan_complete") {
          queryClient.invalidateQueries({ queryKey: ["/api/dashboard/stats"] });
          queryClient.invalidateQueries({ queryKey: ["/api/dashboard/activity"] });
        }
      } catch { /* ignore */ }
    };
    es.onerror = () => { setIsLive(false); };
    return () => es.close();
  }, [queryClient]);

  const [trendDays, setTrendDays] = useState(90);

  const scans: any[] = Array.isArray(scansResp)
    ? scansResp
    : (scansResp as any)?.items ?? [];

  const throughput = buildThroughputData(scans);
  const activityList: any[] = Array.isArray(activity) ? activity : [];

  const s = stats as any;
  const totalScans   = s?.total_scans   ?? 0;
  const activeScans  = s?.active_scans  ?? 0;
  const critical     = s?.critical_findings ?? 0;
  const high         = s?.high_findings ?? 0;
  const riskScore    = s?.risk_score    ?? 0;
  const medium       = s?.medium_findings ?? 0;
  const low          = s?.low_findings  ?? 0;
  const info         = s?.info_findings ?? 0;
  const totalFindings = s?.total_findings ?? 0;

  /* Sparkline data shapes */
  const spTotal   = [2, 3, 2, 4, 5, 4, totalScans || 6];
  const spActive  = [0, 1, 2, 1, 3, 2, activeScans || 1];
  const spCrit    = [1, 2, 1, 3, 2, 2, critical || 1];
  const spHigh    = [2, 3, 4, 3, 4, 3, high || 3];
  const spRisk    = [60, 70, 65, 75, 80, 85, riskScore || 80];

  /* Findings breakdown data */
  const breakdown = [
    { label: "CRITICAL", count: critical,  color: "hsl(var(--critical))" },
    { label: "HIGH",     count: high,      color: "hsl(var(--high))" },
    { label: "MEDIUM",   count: medium,    color: "hsl(var(--medium))" },
    { label: "LOW",      count: low,       color: "hsl(var(--low))" },
    { label: "INFO",     count: info,      color: "hsl(var(--info))" },
  ];
  const maxBreakdown = Math.max(...breakdown.map(b => b.count), 1);

  return (
    <div className="space-y-5">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight flex items-center gap-2">
            Security Operations Console
            {isLive && (
              <span className="flex items-center gap-1 text-xs text-green-400 font-mono">
                <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse inline-block" />
                LIVE
              </span>
            )}
          </h1>
          <p className="text-xs mt-0.5" style={{ color: "hsl(var(--muted-foreground))" }}>
            Live vulnerability assessment and threat surface monitoring.
          </p>
        </div>
        <Button
          onClick={() => setLocation("/scans/new")}
          className="text-sm font-semibold"
          style={{
            background: "linear-gradient(135deg, #7c3aed, #a855f7)",
            color: "white",
            border: "none",
          }}
        >
          <Plus className="w-4 h-4 mr-1.5" />
          NEW SCAN
        </Button>
      </div>

      {/* SLA breach warning strip */}
      {critical > 0 && (
        <div
          className="flex items-center gap-3 rounded-lg px-4 py-2.5 text-xs font-medium cursor-pointer"
          style={{ background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.25)", color: "#f87171" }}
          onClick={() => setLocation("/findings?severity=critical")}
        >
          <span className="w-2 h-2 rounded-full bg-red-400 animate-pulse flex-shrink-0" />
          <span>{critical} critical finding{critical !== 1 ? "s" : ""} require immediate attention — SLA breach risk</span>
          <span className="ml-auto underline">View Critical →</span>
        </div>
      )}

      {/* KPI cards */}
      <div className="grid grid-cols-5 gap-3">
        <KpiCard
          label="Total Scans"
          value={totalScans}
          sublabel={totalScans > 0 ? `+${Math.min(totalScans, 6)}` : undefined}
          valueColor="hsl(var(--foreground))"
          sparkData={spTotal}
          sparkColor="#818cf8"
          onClick={() => setLocation("/scans")}
        />
        <KpiCard
          label="Active Scans"
          value={activeScans}
          valueColor="#22d3ee"
          sparkData={spActive}
          sparkColor="#22d3ee"
          onClick={() => setLocation("/scans?status=running")}
        />
        <KpiCard
          label="Critical"
          value={critical}
          valueColor="#f87171"
          sparkData={spCrit}
          sparkColor="#f87171"
          onClick={() => setLocation("/findings?severity=critical")}
        />
        <KpiCard
          label="High"
          value={high}
          valueColor="#fb923c"
          sparkData={spHigh}
          sparkColor="#fb923c"
          onClick={() => setLocation("/findings?severity=high")}
        />
        <KpiCard
          label="Risk Score"
          value={`${riskScore}`}
          valueColor="#c084fc"
          sparkData={spRisk}
          sparkColor="#c084fc"
          onClick={() => setLocation("/findings")}
        />
      </div>

      {/* Risk trend */}
      <RiskTrendChart />

      {/* Main content: chart + sidebar */}
      <div className="grid grid-cols-5 gap-4" style={{ minHeight: 380 }}>
        {/* Scan throughput area chart */}
        <div
          className="col-span-3 rounded-lg border p-4 flex flex-col"
          style={{ background: "hsl(var(--card))", borderColor: "hsl(var(--border))" }}
        >
          <div className="flex items-center gap-2 mb-4">
            <Activity className="w-4 h-4" style={{ color: "hsl(var(--primary))" }} />
            <span className="text-sm font-medium">Scan Throughput (7 Days)</span>
          </div>
          <div className="flex-1">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={throughput} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="gradScans" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#a855f7" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#a855f7" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gradFindings" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ec4899" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#ec4899" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="date"
                  tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
                  axisLine={false}
                  tickLine={false}
                  allowDecimals={false}
                />
                <Tooltip
                  contentStyle={{
                    background: "hsl(var(--popover))",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: 6,
                    fontSize: 12,
                  }}
                  labelStyle={{ color: "hsl(var(--foreground))" }}
                  itemStyle={{ color: "hsl(var(--muted-foreground))" }}
                />
                <Area
                  type="monotone"
                  dataKey="scans"
                  stroke="#a855f7"
                  strokeWidth={2}
                  fill="url(#gradScans)"
                  name="Scans"
                />
                <Area
                  type="monotone"
                  dataKey="findings"
                  stroke="#ec4899"
                  strokeWidth={2}
                  fill="url(#gradFindings)"
                  name="Findings"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Right sidebar: Findings breakdown + Activity stream */}
        <div className="col-span-2 flex flex-col gap-3">
          {/* Findings breakdown */}
          <div
            className="rounded-lg border p-4 flex flex-col gap-3"
            style={{ background: "hsl(var(--card))", borderColor: "hsl(var(--border))" }}
          >
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full flex-shrink-0" style={{ background: "hsl(var(--primary))" }} />
              <span className="text-sm font-medium">Findings Breakdown</span>
              <span className="ml-auto text-xs font-mono" style={{ color: "hsl(var(--muted-foreground))" }}>
                {totalFindings} total
              </span>
            </div>
            <div className="space-y-2.5">
              {breakdown.map((b) => (
                <div key={b.label} className="flex items-center gap-3">
                  <span className="text-[11px] font-mono w-16 flex-shrink-0 font-semibold" style={{ color: b.color }}>
                    {b.label}
                  </span>
                  <span className="text-[11px] font-mono w-4 text-right flex-shrink-0" style={{ color: b.color }}>
                    {b.count}
                  </span>
                  <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: "hsl(var(--muted))" }}>
                    <div
                      className="h-full rounded-full transition-all"
                      style={{
                        width: `${(b.count / maxBreakdown) * 100}%`,
                        background: b.color,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Live activity stream */}
          <div
            className="rounded-lg border flex-1 flex flex-col overflow-hidden"
            style={{ background: "hsl(var(--card))", borderColor: "hsl(var(--border))" }}
          >
            <div className="flex items-center justify-between px-4 py-2.5 border-b flex-shrink-0" style={{ borderColor: "hsl(var(--border))" }}>
              <div className="flex items-center gap-2 text-sm font-medium">
                <span className="font-mono text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>{">"}_</span>
                <span>Live Activity Stream</span>
              </div>
              <div
                className="text-[10px] font-mono px-1.5 py-0.5 rounded border flex items-center gap-1"
                style={{ color: "#4ade80", borderColor: "rgba(74,222,128,0.3)", background: "rgba(74,222,128,0.07)" }}
              >
                <span className="w-1 h-1 rounded-full bg-green-400 animate-pulse" />
                SSE Connected
              </div>
            </div>
            <div className="flex-1 overflow-y-auto p-3 space-y-2.5 font-mono text-[11px]">
              {activityList.slice(0, 12).map((ev: any) => {
                const tag = activityTag(ev.type);
                const time = new Date(ev.timestamp).toLocaleTimeString("en-US", {
                  hour: "2-digit", minute: "2-digit", second: "2-digit",
                });
                return (
                  <div key={ev.id} className="flex gap-2 leading-relaxed">
                    <span className="flex-shrink-0" style={{ color: "hsl(var(--muted-foreground))" }}>
                      [{time}]
                    </span>
                    <span className="flex-shrink-0 font-semibold" style={{ color: tag.color }}>
                      [{tag.label}]
                    </span>
                    <span className="flex-1 break-all" style={{ color: "hsl(var(--foreground))" }}>
                      {ev.message}
                    </span>
                  </div>
                );
              })}
              {activityList.length === 0 && (
                <div style={{ color: "hsl(var(--muted-foreground))" }}>Awaiting events...</div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Risk Score Trend */}
      {(() => {
        const rawTrend = (s as any)?.risk_trend ?? [];
        const trendData: { date: string; score: number }[] = (Array.isArray(rawTrend) ? rawTrend : [])
          .map((item: any) => ({ date: item.date, score: Math.round((Number(item.risk) || 0) / 10) }))
          .filter((item: any) => item.date != null);
        return (
          <div
            className="rounded-lg border p-4 flex flex-col"
            style={{ background: "hsl(var(--card))", borderColor: "hsl(var(--border))" }}
          >
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <TrendingUp className="w-4 h-4" style={{ color: "hsl(var(--primary))" }} />
                <span className="text-sm font-medium">Risk Score Trend</span>
              </div>
              <div className="flex gap-1">
                {([30, 60, 90] as const).map((d) => (
                  <button
                    key={d}
                    onClick={() => setTrendDays(d)}
                    className="px-2.5 py-0.5 rounded text-xs font-mono transition-all"
                    style={{
                      background: trendDays === d ? "hsl(var(--primary))" : "hsl(var(--muted))",
                      color: trendDays === d ? "hsl(var(--primary-foreground))" : "hsl(var(--muted-foreground))",
                      border: "none",
                      cursor: "pointer",
                    }}
                  >
                    {d}d
                  </button>
                ))}
              </div>
            </div>
            {trendData.length === 0 ? (
              <p className="text-xs text-center py-8" style={{ color: "hsl(var(--muted-foreground))" }}>
                No risk trend data yet
              </p>
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={trendData} margin={{ top: 4, right: 16, left: -20, bottom: 0 }}>
                  <XAxis
                    dataKey="date"
                    tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
                    axisLine={false}
                    tickLine={false}
                    tickFormatter={(d) => format(new Date(d), "MMM d")}
                  />
                  <YAxis
                    domain={[0, 10]}
                    tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "hsl(var(--popover))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: 6,
                      fontSize: 11,
                    }}
                    labelStyle={{ color: "hsl(var(--foreground))" }}
                  />
                  <ReferenceLine
                    y={7}
                    stroke="#ef4444"
                    strokeDasharray="4 4"
                    label={{ value: "High", fill: "#ef4444", fontSize: 10 }}
                  />
                  <ReferenceLine
                    y={4}
                    stroke="#f97316"
                    strokeDasharray="4 4"
                    label={{ value: "Med", fill: "#f97316", fontSize: 10 }}
                  />
                  <Line
                    type="monotone"
                    dataKey="score"
                    stroke="hsl(var(--primary))"
                    dot={false}
                    strokeWidth={2}
                  />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        );
      })()}
    </div>
  );
}
