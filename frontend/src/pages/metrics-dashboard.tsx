import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { TrendingUp, TrendingDown, Minus, AlertTriangle, RefreshCw } from "lucide-react";

function fetchJson(url: string) {
  return fetch(url, { credentials: "include" }).then((r) => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  });
}

interface MttrData { critical: number | null; high: number | null; medium: number | null; low: number | null; overall: number | null }
interface SlaData { [sev: string]: { compliant: number; total: number; pct: number } }
interface FpItem { scanner_name: string; total: number; false_positives: number; fp_rate: number }
interface VelocityItem { target_url: string; current_score: number; previous_score: number; delta: number; trend: "up" | "down" | "stable" }
interface RecurrenceData { recurrent: number; total: number; rate: number }

function SeverityLabel({ sev }: { sev: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  };
  return <span className={`text-xs font-medium px-2 py-0.5 rounded border uppercase ${colors[sev] ?? "bg-muted text-muted-foreground"}`}>{sev}</span>;
}

function MttrCard({ sev, hours }: { sev: string; hours: number | null }) {
  return (
    <div className="rounded-lg p-4 border" style={{ background: "hsl(var(--card))", borderColor: "hsl(var(--border))" }}>
      <div className="flex items-center justify-between mb-2">
        <SeverityLabel sev={sev} />
        <span className="text-xs text-muted-foreground">MTTR</span>
      </div>
      <p className="text-2xl font-bold text-foreground">{hours != null ? `${hours.toFixed(1)}h` : "N/A"}</p>
      <p className="text-xs text-muted-foreground mt-1">Mean time to remediate</p>
    </div>
  );
}

function SlaBar({ sev, data }: { sev: string; data: { compliant: number; total: number; pct: number } }) {
  const pct = data.total > 0 ? data.pct : 100;
  const color = pct >= 90 ? "#22c55e" : pct >= 70 ? "#eab308" : "#ef4444";
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <SeverityLabel sev={sev} />
        <span className="text-sm font-semibold" style={{ color }}>{pct}%</span>
      </div>
      <div className="h-2 rounded-full bg-muted overflow-hidden">
        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: color }} />
      </div>
      <p className="text-xs text-muted-foreground">{data.compliant} / {data.total} within SLA</p>
    </div>
  );
}

export default function MetricsDashboard() {
  const { data: mttr, isLoading: mttrLoading } = useQuery<MttrData>({
    queryKey: ["metrics-mttr"],
    queryFn: () => fetchJson("/api/metrics/mttr"),
  });
  const { data: sla, isLoading: slaLoading } = useQuery<SlaData>({
    queryKey: ["metrics-sla"],
    queryFn: () => fetchJson("/api/metrics/sla-compliance"),
  });
  const { data: fp, isLoading: fpLoading } = useQuery<FpItem[]>({
    queryKey: ["metrics-fp"],
    queryFn: () => fetchJson("/api/metrics/false-positive-rate"),
  });
  const { data: velocity, isLoading: velLoading } = useQuery<VelocityItem[]>({
    queryKey: ["metrics-velocity"],
    queryFn: () => fetchJson("/api/metrics/risk-velocity"),
  });
  const { data: recurrence, isLoading: recLoading } = useQuery<RecurrenceData>({
    queryKey: ["metrics-recurrence"],
    queryFn: () => fetchJson("/api/metrics/recurrence-rate"),
  });

  const loading = mttrLoading || slaLoading || fpLoading || velLoading || recLoading;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Security Metrics</h1>
          <p className="text-sm text-muted-foreground">Advanced analytics: MTTR, SLA compliance, false positives, and risk velocity</p>
        </div>
        {loading && <RefreshCw className="w-4 h-4 animate-spin text-muted-foreground" />}
      </div>

      {/* Recurrence badge */}
      {recurrence && (
        <div className="flex items-center gap-2">
          <span className="text-sm text-muted-foreground">Recurrence Rate:</span>
          <Badge variant={recurrence.rate > 20 ? "destructive" : "secondary"}>
            {recurrence.rate.toFixed(1)}% ({recurrence.recurrent} / {recurrence.total} findings recur)
          </Badge>
        </div>
      )}

      {/* MTTR Cards */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Mean Time to Remediate (MTTR)</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {(["critical", "high", "medium", "low"] as const).map((sev) => (
              <MttrCard key={sev} sev={sev} hours={mttr ? mttr[sev] : null} />
            ))}
          </div>
          {mttr?.overall != null && (
            <p className="text-sm text-muted-foreground mt-4">Overall MTTR: <span className="font-semibold text-foreground">{mttr.overall.toFixed(1)} hours</span></p>
          )}
        </CardContent>
      </Card>

      {/* SLA Compliance */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">SLA Compliance</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {sla && (["critical", "high", "medium", "low"] as const).map((sev) =>
              sla[sev] ? <SlaBar key={sev} sev={sev} data={sla[sev]!} /> : null
            )}
          </div>
          <p className="text-xs text-muted-foreground mt-4">
            SLA windows: Critical=24h, High=7d, Medium=30d, Low=90d
          </p>
        </CardContent>
      </Card>

      {/* False Positive Rate */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">False Positive Rate by Scanner</CardTitle>
        </CardHeader>
        <CardContent>
          {fpLoading ? (
            <p className="text-sm text-muted-foreground">Loading...</p>
          ) : fp && fp.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b" style={{ borderColor: "hsl(var(--border))" }}>
                    <th className="text-left py-2 text-muted-foreground font-medium">Scanner</th>
                    <th className="text-right py-2 text-muted-foreground font-medium">Total</th>
                    <th className="text-right py-2 text-muted-foreground font-medium">False Positives</th>
                    <th className="text-right py-2 text-muted-foreground font-medium">FP Rate</th>
                  </tr>
                </thead>
                <tbody>
                  {fp.map((row) => (
                    <tr key={row.scanner_name} className="border-b" style={{ borderColor: "hsl(var(--border))" }}>
                      <td className="py-2 font-mono text-xs text-foreground">{row.scanner_name}</td>
                      <td className="py-2 text-right text-foreground">{row.total}</td>
                      <td className="py-2 text-right text-foreground">{row.false_positives}</td>
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
            <p className="text-sm text-muted-foreground">No scanner data available yet.</p>
          )}
        </CardContent>
      </Card>

      {/* Risk Velocity */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Risk Velocity by Target</CardTitle>
        </CardHeader>
        <CardContent>
          {velLoading ? (
            <p className="text-sm text-muted-foreground">Loading...</p>
          ) : velocity && velocity.length > 0 ? (
            <div className="space-y-3">
              {velocity.slice(0, 10).map((item) => (
                <div key={item.target_url} className="flex items-center justify-between p-3 rounded-lg border" style={{ borderColor: "hsl(var(--border))" }}>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium text-foreground truncate">{item.target_url}</p>
                    <p className="text-xs text-muted-foreground">Previous: {item.previous_score} → Current: {item.current_score}</p>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0 ml-4">
                    {item.trend === "up" && <TrendingUp className="w-4 h-4 text-red-400" />}
                    {item.trend === "down" && <TrendingDown className="w-4 h-4 text-green-400" />}
                    {item.trend === "stable" && <Minus className="w-4 h-4 text-muted-foreground" />}
                    <span className={`text-sm font-semibold ${item.delta > 0 ? "text-red-400" : item.delta < 0 ? "text-green-400" : "text-muted-foreground"}`}>
                      {item.delta > 0 ? "+" : ""}{item.delta}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <AlertTriangle className="w-4 h-4" />
              No velocity data available. Complete multiple scans on the same targets to see trends.
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
