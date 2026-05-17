import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, CartesianGrid,
} from "recharts";
import { RefreshCw, AlertTriangle } from "lucide-react";

function fetchJson(url: string) {
  return fetch(url, { credentials: "include" }).then((r) => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  });
}

interface TrendItem { date: string; count: number }
interface ScannerPerf { scanner_name: string; total_findings: number; avg_confidence: number; fp_rate: number }
interface TopTarget { id: string; url: string; domain: string; total_findings: number; critical_findings: number; risk_score: number }

export default function AnalyticsEnhanced() {
  const { data: trends, isLoading: trendsLoading, isError: trendsError } = useQuery<TrendItem[]>({
    queryKey: ["analytics-finding-trends"],
    queryFn: () => fetchJson("/api/analytics/finding-trends"),
  });
  const { data: scannerPerf, isLoading: perfLoading, isError: perfError } = useQuery<ScannerPerf[]>({
    queryKey: ["analytics-scanner-perf"],
    queryFn: () => fetchJson("/api/analytics/scanner-performance"),
  });
  const { data: topTargets, isLoading: targetsLoading, isError: targetsError } = useQuery<TopTarget[]>({
    queryKey: ["analytics-top-targets"],
    queryFn: () => fetchJson("/api/analytics/top-vulnerable-targets"),
  });

  const anyError = trendsError || perfError || targetsError;
  if (anyError) return (
    <div className="flex flex-col items-center justify-center h-64 gap-4">
      <AlertTriangle className="w-12 h-12 text-red-400" />
      <p className="text-muted-foreground text-sm">Failed to load data. Please try again.</p>
      <Button variant="outline" size="sm" onClick={() => window.location.reload()}>Retry</Button>
    </div>
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Enhanced Analytics</h1>
          <p className="text-sm text-muted-foreground">Finding trends, scanner performance, and vulnerable target insights</p>
        </div>
        {(trendsLoading || perfLoading || targetsLoading) && (
          <RefreshCw className="w-4 h-4 animate-spin text-muted-foreground" />
        )}
      </div>

      {/* Finding Trends */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Finding Trends — Last 30 Days</CardTitle>
        </CardHeader>
        <CardContent>
          {trendsLoading ? (
            <div className="p-6 space-y-4">
              <Skeleton className="h-8 w-48" />
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
                  <Line type="monotone" dataKey="count" stroke="#7c3aed" strokeWidth={2} dot={false} name="Findings" />
                </LineChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No trend data available yet.</p>
          )}
        </CardContent>
      </Card>

      {/* Scanner Performance */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Scanner Performance</CardTitle>
        </CardHeader>
        <CardContent>
          {perfLoading ? (
            <div className="p-6 space-y-3">
              <Skeleton className="h-8 w-64" />
              {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-12 w-full rounded" />)}
            </div>
          ) : scannerPerf && scannerPerf.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b" style={{ borderColor: "hsl(var(--border))" }}>
                    <th className="text-left py-2 text-muted-foreground font-medium">Scanner</th>
                    <th className="text-right py-2 text-muted-foreground font-medium">Findings</th>
                    <th className="text-right py-2 text-muted-foreground font-medium">Avg Confidence</th>
                    <th className="text-right py-2 text-muted-foreground font-medium">FP Rate</th>
                  </tr>
                </thead>
                <tbody>
                  {scannerPerf.map((row) => (
                    <tr key={row.scanner_name} className="border-b" style={{ borderColor: "hsl(var(--border))" }}>
                      <td className="py-2 font-mono text-xs text-foreground">{row.scanner_name}</td>
                      <td className="py-2 text-right text-foreground">{row.total_findings}</td>
                      <td className="py-2 text-right text-foreground">{(row.avg_confidence * 100).toFixed(0)}%</td>
                      <td className="py-2 text-right">
                        <span className={row.fp_rate > 20 ? "text-red-400" : row.fp_rate > 10 ? "text-yellow-400" : "text-green-400"}>
                          {row.fp_rate.toFixed(1)}%
                        </span>
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

      {/* Top Vulnerable Targets Bar Chart */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Top Vulnerable Targets</CardTitle>
        </CardHeader>
        <CardContent>
          {targetsLoading ? (
            <div className="p-6 space-y-4">
              <Skeleton className="h-8 w-48" />
              <Skeleton className="h-64 w-full rounded-lg" />
            </div>
          ) : topTargets && topTargets.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={topTargets.map((t) => ({ name: t.domain || t.url, findings: t.total_findings, risk: t.risk_score }))}
                  margin={{ top: 5, right: 10, left: -20, bottom: 40 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="name" tick={{ fontSize: 9, fill: "hsl(var(--muted-foreground))" }} angle={-30} textAnchor="end" />
                  <YAxis tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
                  <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 6 }} />
                  <Bar dataKey="findings" fill="#7c3aed" name="Findings" radius={[3, 3, 0, 0]} />
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
