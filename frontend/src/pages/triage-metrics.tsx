import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from "recharts";
import {
  ShieldOff, TrendingDown, TrendingUp, Clock, Target,
  RefreshCw, AlertTriangle, CheckCircle2, BarChart2,
} from "lucide-react";

interface TriageStats {
  fp_rate: number;
  total_findings: number;
  total_fp: number;
  confirmed_fp: number;
  rejected_fp: number;
  pending_review: number;
  avg_triage_time_hours: number;
  fp_by_reason: { reason: string; count: number }[];
  weekly_fp_trend: { week: string; fp_count: number; total: number; fp_rate: number }[];
  scanner_accuracy: { scanner: string; fp_rate: number; total: number }[];
}

const REASON_LABELS: Record<string, string> = {
  test_environment: "Test Env",
  accepted_risk: "Accepted Risk",
  compensating_control: "Comp. Control",
  not_applicable: "N/A",
  duplicate: "Duplicate",
  other: "Other",
};

const PIE_COLORS = ["#6366f1", "#f59e0b", "#10b981", "#ef4444", "#8b5cf6", "#06b6d4"];

function StatCard({ label, value, sub, icon: Icon, trend, color }: {
  label: string; value: string | number; sub?: string;
  icon: React.ElementType; trend?: "up" | "down" | "neutral"; color?: string;
}) {
  return (
    <Card className="border-border/50">
      <CardContent className="p-5">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs text-muted-foreground">{label}</span>
          <Icon className={`w-4 h-4 ${color ?? "text-muted-foreground"}`} />
        </div>
        <div className="text-2xl font-bold">{value}</div>
        {sub && (
          <div className="flex items-center gap-1 mt-1 text-xs text-muted-foreground">
            {trend === "up" && <TrendingUp className="w-3 h-3 text-green-400" />}
            {trend === "down" && <TrendingDown className="w-3 h-3 text-red-400" />}
            {sub}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function GaugeSvg({ value, label, color }: { value: number; label: string; color: string }) {
  const pct = Math.min(Math.max(value, 0), 100) / 100;
  const r = 54;
  const cx = 70;
  const cy = 70;
  const startAngle = Math.PI;
  const endAngle = 2 * Math.PI;
  const total = endAngle - startAngle;
  const filled = total * pct;

  const arc = (angle: number) => [
    cx + r * Math.cos(angle),
    cy + r * Math.sin(angle),
  ] as [number, number];

  const [sx, sy] = arc(startAngle);
  const [ex, ey] = arc(startAngle + filled);
  const large = filled > Math.PI ? 1 : 0;

  return (
    <svg width="140" height="80" viewBox="0 0 140 80">
      <path d={`M ${arc(startAngle)[0]} ${arc(startAngle)[1]} A ${r} ${r} 0 1 1 ${arc(endAngle)[0]} ${arc(endAngle)[1]}`}
        fill="none" stroke="hsl(var(--muted))" strokeWidth="10" strokeLinecap="round" />
      {pct > 0 && (
        <path d={`M ${sx} ${sy} A ${r} ${r} 0 ${large} 1 ${ex} ${ey}`}
          fill="none" stroke={color} strokeWidth="10" strokeLinecap="round" />
      )}
      <text x={cx} y={cy - 4} textAnchor="middle" fontSize="18" fontWeight="700" fill="currentColor">{value}%</text>
      <text x={cx} y={cy + 12} textAnchor="middle" fontSize="9" fill="hsl(var(--muted-foreground))">{label}</text>
    </svg>
  );
}

export default function TriageMetricsPage() {
  const { data, isLoading, refetch } = useQuery<TriageStats>({
    queryKey: ["triage-stats"],
    queryFn: async () => {
      const res = await fetch("/api/triage/stats");
      if (!res.ok) throw new Error("Failed to load stats");
      return res.json();
    },
    staleTime: 60_000,
  });

  const fpRate = data?.fp_rate ?? 0;
  const trend = data?.weekly_fp_trend ?? [];
  const byReason = (data?.fp_by_reason ?? []).map((r) => ({
    ...r,
    name: REASON_LABELS[r.reason] ?? r.reason,
  }));
  const scannerAccuracy = data?.scanner_accuracy ?? [];

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <BarChart2 className="w-6 h-6 text-primary" />
            Triage Metrics Dashboard
          </h1>
          <p className="text-muted-foreground text-sm mt-1">FP/FN rates, scanner accuracy, and triage performance KPIs.</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* KPI Strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="False Positive Rate" value={`${fpRate}%`} icon={ShieldOff}
          color={fpRate > 30 ? "text-red-400" : fpRate > 15 ? "text-yellow-400" : "text-green-400"}
          sub="across all findings" trend={fpRate > 20 ? "down" : "up"} />
        <StatCard label="Pending Review" value={data?.pending_review ?? "—"} icon={Clock} color="text-yellow-400" sub="awaiting four-eyes" />
        <StatCard label="Avg Triage Time" value={data?.avg_triage_time_hours !== undefined ? `${data.avg_triage_time_hours}h` : "—"} icon={Target} color="text-blue-400" sub="median time to decision" />
        <StatCard label="Confirmed FPs" value={data?.confirmed_fp ?? "—"} icon={CheckCircle2} color="text-green-400"
          sub={data ? `of ${data.total_fp} marked` : undefined} />
      </div>

      {/* Gauge row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="border-border/50">
          <CardHeader className="pb-2"><CardTitle className="text-sm">FP Rate</CardTitle></CardHeader>
          <CardContent className="flex justify-center py-2">
            {isLoading ? <div className="h-20 w-full bg-muted animate-pulse rounded" /> : (
              <GaugeSvg value={fpRate} label="False Positive %" color={fpRate > 30 ? "#ef4444" : fpRate > 15 ? "#f59e0b" : "#10b981"} />
            )}
          </CardContent>
        </Card>

        <Card className="border-border/50">
          <CardHeader className="pb-2"><CardTitle className="text-sm">FP by Reason</CardTitle></CardHeader>
          <CardContent className="h-40">
            {isLoading ? <div className="h-full bg-muted animate-pulse rounded" /> : byReason.length === 0 ? (
              <div className="flex h-full items-center justify-center text-xs text-muted-foreground">No data</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={byReason} dataKey="count" nameKey="name" cx="50%" cy="50%" outerRadius={55} paddingAngle={2}>
                    {byReason.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                  </Pie>
                  <Tooltip formatter={(v: number) => [`${v}`, "Count"]} contentStyle={{ background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: "8px" }} />
                  <Legend iconSize={8} wrapperStyle={{ fontSize: "10px" }} />
                </PieChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card className="border-border/50">
          <CardHeader className="pb-2"><CardTitle className="text-sm">Triage Pipeline</CardTitle></CardHeader>
          <CardContent className="space-y-3 pt-2">
            {isLoading ? Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="h-4 bg-muted animate-pulse rounded" />
            )) : [
              { label: "Total FP Marked", value: data?.total_fp ?? 0, color: "bg-indigo-500" },
              { label: "Confirmed", value: data?.confirmed_fp ?? 0, color: "bg-green-500" },
              { label: "Rejected", value: data?.rejected_fp ?? 0, color: "bg-red-500" },
              { label: "Pending", value: data?.pending_review ?? 0, color: "bg-yellow-500" },
            ].map(({ label, value, color }) => (
              <div key={label}>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-muted-foreground">{label}</span>
                  <span className="font-medium">{value}</span>
                </div>
                <div className="h-1.5 rounded-full bg-muted overflow-hidden">
                  <div className={`h-full ${color} rounded-full`}
                    style={{ width: `${data?.total_findings ? Math.min((value / data.total_findings) * 100, 100) : 0}%` }} />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Weekly FP Trend */}
      <Card className="border-border/50">
        <CardHeader><CardTitle className="text-sm">Weekly FP Rate Trend (8 weeks)</CardTitle></CardHeader>
        <CardContent className="h-56">
          {isLoading ? <div className="h-full bg-muted animate-pulse rounded" /> : trend.length === 0 ? (
            <div className="flex h-full items-center justify-center text-xs text-muted-foreground">No trend data available</div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trend} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                <defs>
                  <linearGradient id="fpGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis dataKey="week" tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
                <YAxis tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" unit="%" />
                <Tooltip
                  formatter={(v: number) => [`${v}%`, "FP Rate"]}
                  contentStyle={{ background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: "8px", fontSize: "12px" }} />
                <Area type="monotone" dataKey="fp_rate" stroke="#6366f1" fill="url(#fpGrad)" strokeWidth={2} dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </CardContent>
      </Card>

      {/* Scanner accuracy */}
      {scannerAccuracy.length > 0 && (
        <Card className="border-border/50">
          <CardHeader><CardTitle className="text-sm">Scanner FP Rates</CardTitle></CardHeader>
          <CardContent className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={scannerAccuracy} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis dataKey="scanner" tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
                <YAxis tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" unit="%" />
                <Tooltip
                  formatter={(v: number) => [`${v}%`, "FP Rate"]}
                  contentStyle={{ background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: "8px", fontSize: "12px" }} />
                <Bar dataKey="fp_rate" fill="#6366f1" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
