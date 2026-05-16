import { useQuery } from "@tanstack/react-query";
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid, Legend, Cell,
} from "recharts";
import { format, parseISO, startOfMonth } from "date-fns";
import { useState } from "react";
import { Loader2, Activity, Clock, Zap, Target, AlertTriangle } from "lucide-react";

function AiNarrativePanel({ scanId }: { scanId: string }) {
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);

  async function generate() {
    setText(""); setLoading(true);
    try {
      const res = await fetch(`/api/ai/executive-narrative/${scanId}`, { method: "POST", credentials: "include" });
      if (!res.ok) throw new Error();
      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n"); buf = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try { const d = JSON.parse(line.slice(6)); if (d.content) setText(p => p + d.content); } catch { /* ignore */ }
        }
      }
    } catch { setText("Failed to generate narrative."); }
    finally { setLoading(false); }
  }

  return (
    <div className="border rounded-lg p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="font-semibold text-sm">AI Executive Narrative</h3>
        <button onClick={generate} disabled={loading}
          className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md font-medium transition-colors"
          style={{ background: "#7c3aed", color: "white" }}>
          {loading ? <><Loader2 className="w-3 h-3 animate-spin" />Generating…</> : <><Activity className="w-3 h-3" />Generate</>}
        </button>
      </div>
      {text ? (
        <div className="text-sm leading-relaxed space-y-3 text-muted-foreground">
          {text.split("\n\n").filter(Boolean).map((p, i) => <p key={i}>{p}</p>)}
          {loading && <span className="inline-block w-2 h-4 bg-violet-400 animate-pulse ml-1 align-middle" />}
        </div>
      ) : loading ? (
        <div className="flex items-center gap-2 text-sm text-muted-foreground py-4">
          <Loader2 className="w-4 h-4 animate-spin" /> Generating AI narrative…
        </div>
      ) : (
        <p className="text-sm text-muted-foreground py-4 text-center">Click Generate to create an AI-powered executive briefing for this scan.</p>
      )}
    </div>
  );
}

export default function Executive() {
  const { data: scans = [] } = useQuery<Array<Record<string, unknown>>>({
    queryKey: ["/api/scan-jobs"],
    queryFn: () =>
      fetch("/api/scan-jobs?page_size=100", { credentials: "include" })
        .then((r) => r.json())
        .then((d) => d.items ?? []),
  });

  const completed = scans.filter((s) => s.status === "completed");
  const running = scans.filter((s) => s.status === "running" || s.status === "queued");
  const avgRisk = completed.length > 0
    ? Math.round(completed.reduce((sum, s) => sum + (Number(s.risk_score) || 0), 0) / completed.length)
    : 0;

  // Risk score trend: last 10 completed scans chronologically
  const riskTrend = completed
    .slice()
    .sort((a, b) => new Date(String(a.created_at)).getTime() - new Date(String(b.created_at)).getTime())
    .slice(-10)
    .map((s) => ({
      date: s.created_at ? format(new Date(String(s.created_at)), "MM/dd") : "—",
      risk: Number(s.risk_score) || 0,
    }));

  // Monthly findings by severity — derive from scan counts (if findings_summary available)
  const monthlySeverity: Record<string, { month: string; critical: number; high: number; medium: number; low: number }> = {};
  for (const scan of completed) {
    if (!scan.created_at) continue;
    const key = format(startOfMonth(parseISO(String(scan.created_at))), "MMM yy");
    if (!monthlySeverity[key]) monthlySeverity[key] = { month: key, critical: 0, high: 0, medium: 0, low: 0 };
    const fs = scan.findings_summary as Record<string, number> | undefined;
    if (fs) {
      monthlySeverity[key].critical += fs.critical ?? 0;
      monthlySeverity[key].high += fs.high ?? 0;
      monthlySeverity[key].medium += fs.medium ?? 0;
      monthlySeverity[key].low += fs.low ?? 0;
    }
  }
  const monthlyData = Object.values(monthlySeverity).slice(-6);

  const latestScan = completed.sort((a, b) =>
    new Date(String(b.created_at)).getTime() - new Date(String(a.created_at)).getTime())[0];

  const { data: execMetrics } = useQuery<{
    mttd_hours: number;
    mttr_days: number;
    open_critical: number;
    remediation_velocity: number;
    vulnerability_density: number;
    top_targets: Array<{ url: string; finding_count: number; risk_score: number }>;
  }>({
    queryKey: ["/api/analytics/metrics/executive"],
    queryFn: () =>
      fetch("/api/analytics/metrics/executive", { credentials: "include" }).then((r) => r.json()),
  });

  const BAR_COLORS = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#3b82f6"];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold mb-1">Executive Dashboard</h1>
        <p className="text-muted-foreground">High-level security posture overview for leadership.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="border rounded-lg p-4">
          <div className="text-3xl font-bold">{scans.length}</div>
          <div className="text-sm text-muted-foreground">Total Scans</div>
        </div>
        <div className="border rounded-lg p-4">
          <div className="text-3xl font-bold text-green-500">{completed.length}</div>
          <div className="text-sm text-muted-foreground">Completed</div>
        </div>
        <div className="border rounded-lg p-4">
          <div className="text-3xl font-bold text-yellow-500">{running.length}</div>
          <div className="text-sm text-muted-foreground">In Progress</div>
        </div>
        <div className="border rounded-lg p-4">
          <div className={`text-3xl font-bold ${avgRisk >= 70 ? "text-red-500" : avgRisk >= 40 ? "text-orange-500" : "text-green-500"}`}>{avgRisk}</div>
          <div className="text-sm text-muted-foreground">Avg Risk Score</div>
        </div>
      </div>

      {/* Trend Charts */}
      {riskTrend.length > 1 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="border rounded-lg p-4">
            <h2 className="font-semibold mb-4 text-sm">Risk Score Trend</h2>
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={riskTrend} margin={{ top: 5, right: 10, bottom: 0, left: -20 }}>
                <defs>
                  <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#7c3aed" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#7c3aed" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" opacity={0.1} />
                <XAxis dataKey="date" tick={{ fontSize: 11 }} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} />
                <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8 }} />
                <Area type="monotone" dataKey="risk" stroke="#7c3aed" fill="url(#riskGrad)" strokeWidth={2} dot={{ r: 3 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {monthlyData.length > 0 && (
            <div className="border rounded-lg p-4">
              <h2 className="font-semibold mb-4 text-sm">Monthly Findings by Severity</h2>
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={monthlyData} margin={{ top: 5, right: 10, bottom: 0, left: -20 }}>
                  <CartesianGrid strokeDasharray="3 3" opacity={0.1} />
                  <XAxis dataKey="month" tick={{ fontSize: 11 }} />
                  <YAxis tick={{ fontSize: 11 }} />
                  <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8 }} />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  <Bar dataKey="critical" fill="#ef4444" radius={[2, 2, 0, 0]} />
                  <Bar dataKey="high" fill="#f97316" radius={[2, 2, 0, 0]} />
                  <Bar dataKey="medium" fill="#eab308" radius={[2, 2, 0, 0]} />
                  <Bar dataKey="low" fill="#22c55e" radius={[2, 2, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      )}

      {/* ── KPI Metrics Row ── */}
      {execMetrics && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            {
              label: "MTTD",
              value: `${execMetrics.mttd_hours}h`,
              sub: "Mean time to detect",
              icon: <Clock className="w-4 h-4" />,
              color: "#7c3aed",
            },
            {
              label: "MTTR",
              value: `${execMetrics.mttr_days}d`,
              sub: "Mean time to remediate",
              icon: <Zap className="w-4 h-4" />,
              color: "#3b82f6",
            },
            {
              label: "Velocity",
              value: `${execMetrics.remediation_velocity}/wk`,
              sub: "Findings closed per week",
              icon: <Activity className="w-4 h-4" />,
              color: "#22c55e",
            },
            {
              label: "Vuln Density",
              value: `${execMetrics.vulnerability_density}/target`,
              sub: "Findings per target",
              icon: <Target className="w-4 h-4" />,
              color: execMetrics.vulnerability_density > 5 ? "#ef4444" : "#eab308",
            },
          ].map((kpi) => (
            <div key={kpi.label} className="border rounded-lg p-4">
              <div className="flex items-center gap-2 mb-1" style={{ color: kpi.color }}>
                {kpi.icon}
                <span className="text-xs font-semibold uppercase tracking-wider">{kpi.label}</span>
              </div>
              <div className="text-2xl font-bold" style={{ color: kpi.color }}>{kpi.value}</div>
              <div className="text-xs text-muted-foreground mt-0.5">{kpi.sub}</div>
            </div>
          ))}
        </div>
      )}

      {execMetrics && execMetrics.open_critical > 0 && (
        <div className="flex items-center gap-2 px-4 py-3 rounded-lg border border-destructive/30 bg-destructive/10 text-sm text-destructive">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          <span><strong>{execMetrics.open_critical}</strong> open critical finding{execMetrics.open_critical !== 1 ? "s" : ""} require immediate attention.</span>
        </div>
      )}

      {/* ── Top 5 Most Vulnerable Targets ── */}
      {execMetrics && execMetrics.top_targets.length > 0 && (
        <div className="border rounded-lg p-4">
          <h2 className="font-semibold mb-4 text-sm">Top Vulnerable Targets</h2>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart
              data={execMetrics.top_targets}
              layout="vertical"
              margin={{ top: 0, right: 16, bottom: 0, left: 0 }}
            >
              <CartesianGrid strokeDasharray="3 3" opacity={0.1} horizontal={false} />
              <XAxis type="number" tick={{ fontSize: 11 }} />
              <YAxis
                type="category"
                dataKey="url"
                width={140}
                tick={{ fontSize: 10 }}
                tickFormatter={(v: string) => v.length > 22 ? `${v.slice(0, 22)}…` : v}
              />
              <Tooltip
                contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8 }}
                formatter={(value: number) => [`${value} findings`, "Count"]}
              />
              <Bar dataKey="finding_count" radius={[0, 4, 4, 0]}>
                {execMetrics.top_targets.map((_, i) => (
                  <Cell key={i} fill={BAR_COLORS[i % BAR_COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* AI Narrative for latest scan */}
      {latestScan && <AiNarrativePanel scanId={String(latestScan._id)} />}

      {/* Recent Scans Table */}
      <div className="border rounded-lg p-4">
        <h2 className="font-semibold mb-3">Recent Scans</h2>
        {scans.length === 0 ? (
          <p className="text-muted-foreground text-sm">No scans yet.</p>
        ) : (
          <div className="space-y-2">
            {scans
              .slice()
              .sort((a, b) => new Date(String(b.created_at)).getTime() - new Date(String(a.created_at)).getTime())
              .slice(0, 10)
              .map((scan, i) => (
                <div key={i} className="flex items-center justify-between text-sm py-1 border-b last:border-0">
                  <span className="font-medium truncate max-w-xs">{String(scan.target_url ?? "Unknown")}</span>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className="text-muted-foreground">{scan.created_at ? new Date(String(scan.created_at)).toLocaleDateString() : "—"}</span>
                    <span className={`capitalize px-2 py-0.5 rounded text-xs font-medium ${
                      scan.status === "completed" ? "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400" :
                      scan.status === "running" ? "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400" :
                      "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400"
                    }`}>{String(scan.status ?? "unknown")}</span>
                    <span className={`font-semibold ${Number(scan.risk_score) >= 70 ? "text-red-500" : Number(scan.risk_score) >= 40 ? "text-orange-500" : "text-green-500"}`}>
                      {scan.risk_score != null ? `${scan.risk_score}/100` : "—"}
                    </span>
                  </div>
                </div>
              ))}
          </div>
        )}
      </div>
    </div>
  );
}
