import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar,
  CartesianGrid, Legend,
} from "recharts";
import { RefreshCw, AlertTriangle, ShieldAlert, Zap, Target, Activity } from "lucide-react";

function fetchJson(url: string) {
  return fetch(url, { credentials: "include" }).then((r) => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  });
}

interface TrendItem { date: string; count: number; critical: number }
interface ScannerPerf { scanner_name: string; total_findings: number; avg_confidence: number; fp_rate: number }
interface TopTarget { id: string; url: string; domain: string; total_findings: number; critical_findings: number; risk_score: number }
interface ExecutiveMetrics {
  open_critical: number;
  remediation_velocity: number;
  vulnerability_density: number;
  mttr_days: number;
}

// ── KPI Card ──────────────────────────────────────────────────────────────────
function KpiCard({
  label, value, sub, icon: Icon, color,
}: {
  label: string; value: string | number; sub?: string;
  icon: React.ElementType; color: string;
}) {
  return (
    <Card>
      <CardContent className="pt-5 pb-4 flex items-start gap-4">
        <div className={`p-2 rounded-lg ${color} shrink-0`}>
          <Icon className="w-5 h-5 text-white" />
        </div>
        <div className="min-w-0">
          <p className="text-xs text-muted-foreground leading-none mb-1">{label}</p>
          <p className="text-2xl font-bold text-foreground leading-none">{value}</p>
          {sub && <p className="text-xs text-muted-foreground mt-1">{sub}</p>}
        </div>
      </CardContent>
    </Card>
  );
}

// ── FP Rate progress bar ──────────────────────────────────────────────────────
function FpBar({ rate }: { rate: number }) {
  const color = rate > 20 ? "bg-red-500" : rate > 10 ? "bg-yellow-400" : "bg-green-500";
  const textColor = rate > 20 ? "text-red-400" : rate > 10 ? "text-yellow-400" : "text-green-400";
  return (
    <div className="flex items-center gap-2 justify-end">
      <span className={`text-xs font-mono w-10 text-right ${textColor}`}>{rate.toFixed(1)}%</span>
      <div className="w-20 h-2 rounded-full bg-muted overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ${color}`}
          style={{ width: `${Math.min(rate, 100)}%` }}
        />
      </div>
    </div>
  );
}

export default function AnalyticsEnhanced() {
  const { data: trends, isLoading: trendsLoading, isError: trendsError, refetch: refetchTrends } = useQuery<TrendItem[]>({
    queryKey: ["analytics-finding-trends"],
    queryFn: () => fetchJson("/api/analytics/finding-trends"),
  });
  const { data: scannerPerf, isLoading: perfLoading, isError: perfError, refetch: refetchPerf } = useQuery<ScannerPerf[]>({
    queryKey: ["analytics-scanner-perf"],
    queryFn: () => fetchJson("/api/analytics/scanner-performance"),
  });
  const { data: topTargets, isLoading: targetsLoading, isError: targetsError, refetch: refetchTargets } = useQuery<TopTarget[]>({
    queryKey: ["analytics-top-targets"],
    queryFn: () => fetchJson("/api/analytics/top-vulnerable-targets"),
  });
  const { data: exec, isLoading: execLoading, isError: execError, refetch: refetchExec } = useQuery<ExecutiveMetrics>({
    queryKey: ["analytics-executive"],
    queryFn: () => fetchJson("/api/analytics/metrics/executive"),
  });

  const isRefreshing = trendsLoading || perfLoading || targetsLoading || execLoading;

  function retryAll() {
    refetchTrends(); refetchPerf(); refetchTargets(); refetchExec();
  }

  const anyError = trendsError || perfError || targetsError || execError;
  if (anyError) return (
    <div className="flex flex-col items-center justify-center h-64 gap-4">
      <AlertTriangle className="w-12 h-12 text-red-400" />
      <p className="text-muted-foreground text-sm">Failed to load data. Please try again.</p>
      <Button variant="outline" size="sm" onClick={retryAll}>Retry</Button>
    </div>
  );

  // derive top scanner name from scanner perf data
  const topScanner = scannerPerf?.[0]?.scanner_name ?? "—";
  const totalFindings = trends?.reduce((s, d) => s + d.count, 0) ?? 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Enhanced Analytics</h1>
          <p className="text-sm text-muted-foreground">Finding trends, scanner performance, and vulnerable target insights</p>
        </div>
        {isRefreshing && <RefreshCw className="w-4 h-4 animate-spin text-muted-foreground" />}
      </div>

      {/* ── KPI Summary Cards ─────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {execLoading || trendsLoading || perfLoading ? (
          Array.from({ length: 4 }).map((_, i) => (
            <Card key={i}><CardContent className="pt-5 pb-4"><Skeleton className="h-16 w-full" /></CardContent></Card>
          ))
        ) : (
          <>
            <KpiCard
              label="Open Critical"
              value={exec?.open_critical ?? 0}
              sub="unresolved findings"
              icon={ShieldAlert}
              color="bg-red-500"
            />
            <KpiCard
              label="30-Day Findings"
              value={totalFindings}
              sub="across all scanners"
              icon={Activity}
              color="bg-violet-600"
            />
            <KpiCard
              label="Remediation Velocity"
              value={exec?.remediation_velocity ?? 0}
              sub="resolved last 7 days"
              icon={Zap}
              color="bg-green-600"
            />
            <KpiCard
              label="Top Scanner"
              value={topScanner}
              sub={`${scannerPerf?.[0]?.total_findings ?? 0} findings`}
              icon={Target}
              color="bg-blue-600"
            />
          </>
        )}
      </div>

      {/* ── Dual-Line Finding Trends ───────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Finding Trends — Last 30 Days</CardTitle>
        </CardHeader>
        <CardContent>
          {trendsLoading ? (
            <div className="space-y-4 p-2">
              <Skeleton className="h-64 w-full rounded-lg" />
            </div>
          ) : trends && trends.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trends} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis
                    dataKey="date"
                    tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
                    tickFormatter={(d: string) => d.slice(5)}
                  />
                  <YAxis tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
                  <Tooltip
                    contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 6 }}
                    labelStyle={{ color: "hsl(var(--foreground))", fontSize: 11 }}
                  />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  <Line
                    type="monotone" dataKey="count" stroke="#7c3aed" strokeWidth={2}
                    dot={false} name="All Findings" animationDuration={800}
                  />
                  <Line
                    type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2}
                    dot={false} name="Critical" animationDuration={800} animationBegin={200}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No trend data available yet.</p>
          )}
        </CardContent>
      </Card>

      {/* ── Scanner Performance ────────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Scanner Performance</CardTitle>
        </CardHeader>
        <CardContent>
          {perfLoading ? (
            <div className="space-y-3 p-2">
              {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-10 w-full rounded" />)}
            </div>
          ) : scannerPerf && scannerPerf.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b" style={{ borderColor: "hsl(var(--border))" }}>
                    <th className="text-left py-2 text-muted-foreground font-medium">Scanner</th>
                    <th className="text-right py-2 text-muted-foreground font-medium">Findings</th>
                    <th className="text-right py-2 text-muted-foreground font-medium">Avg Confidence</th>
                    <th className="text-right py-2 text-muted-foreground font-medium pr-1">FP Rate</th>
                  </tr>
                </thead>
                <tbody>
                  {scannerPerf.map((row) => (
                    <tr key={row.scanner_name} className="border-b" style={{ borderColor: "hsl(var(--border))" }}>
                      <td className="py-2 font-mono text-xs text-foreground">{row.scanner_name}</td>
                      <td className="py-2 text-right text-foreground">{row.total_findings}</td>
                      <td className="py-2 text-right text-foreground">{(row.avg_confidence * 100).toFixed(0)}%</td>
                      <td className="py-2 pr-1">
                        <FpBar rate={row.fp_rate} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No scanner performance data yet.</p>
          )}
        </CardContent>
      </Card>

      {/* ── Top Vulnerable Targets ─────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Top Vulnerable Targets</CardTitle>
        </CardHeader>
        <CardContent>
          {targetsLoading ? (
            <div className="space-y-4 p-2">
              <Skeleton className="h-64 w-full rounded-lg" />
            </div>
          ) : topTargets && topTargets.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={topTargets.map((t) => ({ name: t.domain || t.url, findings: t.total_findings, critical: t.critical_findings }))}
                  margin={{ top: 5, right: 10, left: -20, bottom: 40 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="name" tick={{ fontSize: 9, fill: "hsl(var(--muted-foreground))" }} angle={-30} textAnchor="end" />
                  <YAxis tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
                  <Tooltip
                    contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 6 }}
                    labelStyle={{ color: "hsl(var(--foreground))", fontSize: 11 }}
                  />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  <Bar dataKey="findings" fill="#7c3aed" name="All Findings" radius={[3, 3, 0, 0]} animationDuration={800} activeBar={{ fill: "#5b21b6" }} />
                  <Bar dataKey="critical" fill="#ef4444" name="Critical" radius={[3, 3, 0, 0]} animationDuration={800} animationBegin={200} activeBar={{ fill: "#b91c1c" }} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No target data available.</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
