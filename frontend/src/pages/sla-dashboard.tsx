import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, useEffect, useCallback } from "react";
import { Link } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer,
} from "recharts";
import {
  CheckCircle2, AlertTriangle, XCircle, Clock, RefreshCw,
  ExternalLink, Timer, TrendingDown, BarChart2, CalendarDays,
  Plus, ChevronDown, ChevronRight, Download, Zap, MoreVertical,
} from "lucide-react";
import { format, parseISO, isValid } from "date-fns";

// ── Types ─────────────────────────────────────────────────────────────────

interface SlaFinding {
  id: string; title: string; severity: string; endpoint: string;
  sla_due: string; sla_status: string; days_remaining: number;
}
interface SlaSummary {
  total: number; on_track: number; at_risk: number; breached: number; resolved: number;
  compliance_rate: number; findings: SlaFinding[];
}
interface VelocityItem {
  severity: string; avg_days: number | null; target_days: number; count: number; within_sla: number;
}
interface BurnItem { week: string; on_track: number; at_risk: number; breached: number; resolved: number; }

// ── Constants ─────────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22d3ee", info: "#6b7280",
};
const STATUS_CFG: Record<string, { label: string; cls: string; icon: React.ReactNode }> = {
  on_track: { label: "On Track",  cls: "text-emerald-400 bg-emerald-400/10 border-emerald-400/30", icon: <CheckCircle2 className="w-4 h-4 text-emerald-400" /> },
  at_risk:  { label: "At Risk",   cls: "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",  icon: <AlertTriangle className="w-4 h-4 text-yellow-400" /> },
  breached: { label: "Breached",  cls: "text-red-400 bg-red-400/10 border-red-400/30",           icon: <XCircle className="w-4 h-4 text-red-400" /> },
  resolved: { label: "Resolved",  cls: "text-slate-400 bg-slate-400/10 border-slate-400/30",    icon: <CheckCircle2 className="w-4 h-4 text-slate-400" /> },
};
const SLA_POLICY: Record<string, string> = {
  critical: "1 business day", high: "7 business days", medium: "30 business days", low: "90 business days",
};

// ── Live countdown hook ───────────────────────────────────────────────────

function useCountdown(dueDateStr: string): string {
  const [text, setText] = useState("");
  const compute = useCallback(() => {
    const ms = new Date(dueDateStr).getTime() - Date.now();
    if (ms <= 0) return "Overdue";
    const d = Math.floor(ms / 86400000);
    const h = Math.floor((ms % 86400000) / 3600000);
    const m = Math.floor((ms % 3600000) / 60000);
    if (d > 0) return `${d}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  }, [dueDateStr]);
  useEffect(() => {
    setText(compute());
    const t = setInterval(() => setText(compute()), 60000);
    return () => clearInterval(t);
  }, [compute]);
  return text;
}

// ── Countdown cell ────────────────────────────────────────────────────────

function CountdownCell({ finding }: { finding: SlaFinding }) {
  const text = useCountdown(finding.sla_due);
  const isOverdue = finding.sla_status === "breached";
  const isAtRisk = finding.sla_status === "at_risk";
  return (
    <div className="flex items-center gap-1 text-xs font-mono">
      <Timer className={`w-3 h-3 ${isOverdue ? "text-red-400" : isAtRisk ? "text-yellow-400" : "text-muted-foreground"}`} />
      <span className={isOverdue ? "text-red-400 font-bold" : isAtRisk ? "text-yellow-400 font-semibold" : "text-muted-foreground"}>
        {finding.sla_status === "resolved" ? "Done" : text}
      </span>
    </div>
  );
}

// ── SLA heatmap calendar ──────────────────────────────────────────────────

function HeatmapCalendar({ data }: { data: Record<string, number> }) {
  const today = new Date();
  const days: Array<{ date: string; count: number }> = [];
  for (let i = 89; i >= 0; i--) {
    const d = new Date(today.getTime() - i * 86400000);
    const key = d.toISOString().slice(0, 10);
    days.push({ date: key, count: data[key] ?? 0 });
  }
  const max = Math.max(1, ...days.map(d => d.count));
  const weeks: Array<Array<{ date: string; count: number }>> = [];
  for (let i = 0; i < days.length; i += 7) weeks.push(days.slice(i, i + 7));

  return (
    <div className="space-y-2">
      <div className="flex gap-1">
        {weeks.map((week, wi) => (
          <div key={wi} className="flex flex-col gap-1">
            {week.map(d => {
              const intensity = d.count / max;
              const bg = d.count === 0
                ? "hsl(var(--muted))"
                : `rgba(239,68,68,${0.15 + intensity * 0.75})`;
              return (
                <div
                  key={d.date}
                  className="w-3.5 h-3.5 rounded-sm cursor-default transition-all"
                  style={{ background: bg, border: d.count > 0 ? "1px solid rgba(239,68,68,0.3)" : "1px solid transparent" }}
                  title={`${d.date}: ${d.count} breach${d.count !== 1 ? "es" : ""}`}
                />
              );
            })}
          </div>
        ))}
      </div>
      <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
        <span>Less</span>
        {[0, 0.25, 0.5, 0.75, 1].map(v => (
          <div key={v} className="w-3 h-3 rounded-sm" style={{ background: v === 0 ? "hsl(var(--muted))" : `rgba(239,68,68,${0.15 + v * 0.75})` }} />
        ))}
        <span>More</span>
      </div>
    </div>
  );
}

// ── Exception request dialog ──────────────────────────────────────────────

function ExceptionDialog({
  finding,
  onClose,
  onSubmit,
}: {
  finding: SlaFinding;
  onClose: () => void;
  onSubmit: (data: { finding_id: string; reason: string; requested_days: number; analyst: string }) => void;
}) {
  const [reason, setReason] = useState("");
  const [days, setDays] = useState(7);
  const [analyst, setAnalyst] = useState("");
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div className="bg-card border border-border rounded-xl shadow-2xl p-6 w-full max-w-md" onClick={e => e.stopPropagation()}>
        <h3 className="font-semibold mb-1">Request SLA Extension</h3>
        <p className="text-xs text-muted-foreground mb-1"><strong>{finding.title}</strong></p>
        <p className="text-xs text-muted-foreground mb-4">
          Current due: {isValid(parseISO(finding.sla_due)) ? format(parseISO(finding.sla_due), "MMM d, yyyy") : "N/A"}
        </p>
        <div className="space-y-3">
          <div>
            <Label className="text-xs mb-1">Your Name</Label>
            <Input value={analyst} onChange={e => setAnalyst(e.target.value)} placeholder="John Smith" className="h-8 text-sm" />
          </div>
          <div>
            <Label className="text-xs mb-1">Reason for Extension</Label>
            <textarea
              value={reason}
              onChange={e => setReason(e.target.value)}
              placeholder="Explain why more time is needed..."
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm resize-none h-20"
            />
          </div>
          <div>
            <Label className="text-xs mb-1">Days Requested</Label>
            <Input type="number" min={1} max={90} value={days} onChange={e => setDays(Number(e.target.value))} className="h-8 text-sm w-24" />
          </div>
        </div>
        <div className="flex justify-end gap-2 mt-4">
          <Button variant="ghost" size="sm" onClick={onClose}>Cancel</Button>
          <Button size="sm" disabled={!reason || !analyst}
            onClick={() => onSubmit({ finding_id: finding.id, reason, requested_days: days, analyst })}>
            Submit Request
          </Button>
        </div>
      </div>
    </div>
  );
}

// ── SLA Extension dialog for individual findings ──────────────────────────────

function SlaExtendDialog({
  finding,
  onClose,
  onSubmit,
  submitting,
}: {
  finding: SlaFinding;
  onClose: () => void;
  onSubmit: (days: number, reason: string) => void;
  submitting: boolean;
}) {
  const [days, setDays] = useState<7 | 14 | 30>(7);
  const [justification, setJustification] = useState("");
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div className="bg-card border border-border rounded-xl shadow-2xl p-6 w-full max-w-md" onClick={e => e.stopPropagation()}>
        <h3 className="font-semibold mb-1">Extend SLA Deadline</h3>
        <p className="text-xs text-muted-foreground mb-4 font-medium">{finding.title}</p>
        <div className="space-y-4">
          <div>
            <Label className="text-xs mb-2 block">Extend by</Label>
            <div className="flex gap-2">
              {([7, 14, 30] as const).map(d => (
                <button
                  key={d}
                  onClick={() => setDays(d)}
                  className={`flex-1 py-2 rounded-md text-sm border transition-colors ${days === d
                    ? "border-primary bg-primary/10 text-primary font-semibold"
                    : "border-border text-muted-foreground hover:border-primary/50"
                  }`}
                >
                  {d} days
                </button>
              ))}
            </div>
          </div>
          <div>
            <Label className="text-xs mb-1 block">Justification</Label>
            <textarea
              value={justification}
              onChange={e => setJustification(e.target.value)}
              placeholder="Explain why additional time is needed…"
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm resize-none h-20"
            />
          </div>
        </div>
        <div className="flex justify-end gap-2 mt-4">
          <Button variant="ghost" size="sm" onClick={onClose}>Cancel</Button>
          <Button
            size="sm"
            disabled={!justification.trim() || submitting}
            onClick={() => onSubmit(days, justification)}
          >
            {submitting ? "Saving…" : "Extend SLA"}
          </Button>
        </div>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────

export default function SlaDashboard() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [filter, setFilter] = useState("all");
  const [showVelocity, setShowVelocity] = useState(true);
  const [showBurndown, setShowBurndown] = useState(true);
  const [showHeatmap, setShowHeatmap] = useState(true);
  const [showExceptions, setShowExceptions] = useState(false);
  const [exceptionTarget, setExceptionTarget] = useState<SlaFinding | null>(null);
  const [resolving, setResolving] = useState<string | null>(null);
  const [extendTarget, setExtendTarget] = useState<SlaFinding | null>(null);

  const { data, isLoading, refetch } = useQuery<SlaSummary>({
    queryKey: ["/api/sla/summary"],
    queryFn: () => fetch("/api/sla/summary", { credentials: "include" }).then(r => r.json()),
    refetchInterval: 30000,
  });

  const { data: velocity = [] } = useQuery<VelocityItem[]>({
    queryKey: ["/api/sla/velocity"],
    queryFn: () => fetch("/api/sla/velocity", { credentials: "include" }).then(r => r.json()),
  });

  const { data: burnDown = [] } = useQuery<BurnItem[]>({
    queryKey: ["/api/sla/burn-down"],
    queryFn: () => fetch("/api/sla/burn-down", { credentials: "include" }).then(r => r.json()),
  });

  const { data: heatmapData = {} } = useQuery<Record<string, number>>({
    queryKey: ["/api/sla/heatmap"],
    queryFn: () => fetch("/api/sla/heatmap", { credentials: "include" }).then(r => r.json()),
  });

  const { data: exceptions = [] } = useQuery<any[]>({
    queryKey: ["/api/sla/exceptions"],
    queryFn: () => fetch("/api/sla/exceptions", { credentials: "include" }).then(r => r.json()),
  });

  const createException = useMutation({
    mutationFn: (body: object) =>
      fetch("/api/sla/exceptions", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/sla/exceptions"] });
      setExceptionTarget(null);
      toast({ title: "Extension request submitted" });
    },
  });

  const reviewException = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      fetch(`/api/sla/exceptions/${id}`, {
        method: "PATCH", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status, reviewer: "Admin" }),
      }).then(r => r.json()),
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["/api/sla/exceptions"] });
      toast({ title: vars.status === "approved" ? "Exception approved" : "Exception denied" });
    },
  });

  // A. Enforce Now
  const enforce = useMutation({
    mutationFn: () =>
      fetch("/api/sla/enforce", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      }).then(r => r.json()),
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ["/api/sla/summary"] });
      toast({ title: `SLA enforcement complete — ${result.breached ?? 0} findings marked` });
    },
    onError: () => {
      toast({ title: "Enforcement failed", variant: "destructive" });
    },
  });

  // B. Export SLA Report
  async function exportSlaReport() {
    const res = await fetch("/api/sla/report", { credentials: "include" });
    const report: Array<{ severity: string; total: number; breached: number; at_risk: number; compliant: number }> = await res.json();
    const header = "Severity,Total,Breached,At Risk,Compliant";
    const rows = report.map(r => `${r.severity},${r.total},${r.breached},${r.at_risk},${r.compliant}`);
    const csvContent = [header, ...rows].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "sla-report.csv"; a.click();
    URL.revokeObjectURL(url);
  }

  // C. SLA Extension for individual findings
  const extendSla = useMutation({
    mutationFn: ({ id, days, reason }: { id: string; days: number; reason: string }) =>
      fetch(`/api/findings/${id}`, {
        method: "PATCH", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sla_extended_days: days, sla_extension_reason: reason }),
      }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/sla/summary"] });
      setExtendTarget(null);
      toast({ title: "SLA deadline extended" });
    },
    onError: () => {
      toast({ title: "Failed to extend SLA", variant: "destructive" });
    },
  });

  const handleResolve = async (id: string) => {
    setResolving(id);
    try {
      await fetch(`/api/sla/finding/${id}/resolve`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ note: "Marked resolved via SLA dashboard" }),
      });
      await refetch();
    } catch { }
    setResolving(null);
  };

  const filtered = data?.findings.filter(f => filter === "all" || f.sla_status === filter) ?? [];
  const pendingExceptions = exceptions.filter((e: any) => e.status === "pending");

  if (isLoading) return (
    <div className="flex items-center justify-center h-64 text-muted-foreground">
      <RefreshCw className="w-5 h-5 animate-spin mr-2" />Loading SLA data…
    </div>
  );
  if (!data) return null;

  const scoreColor = data.compliance_rate >= 80 ? "#22c55e" : data.compliance_rate >= 60 ? "#eab308" : "#ef4444";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
            <Clock className="w-7 h-7" />
            SLA Tracking
          </h1>
          <p className="text-muted-foreground mt-1">
            Live countdowns, velocity metrics, burn-down chart, and exception workflow.
          </p>
        </div>
        <div className="flex gap-2">
          {pendingExceptions.length > 0 && (
            <Button variant="outline" size="sm" className="border-yellow-500/30 text-yellow-400"
              onClick={() => setShowExceptions(v => !v)}>
              <AlertTriangle className="w-4 h-4 mr-1.5" />{pendingExceptions.length} Pending Exception{pendingExceptions.length !== 1 ? "s" : ""}
            </Button>
          )}
          <Button variant="outline" size="sm" onClick={exportSlaReport}>
            <Download className="w-4 h-4 mr-1.5" />Export SLA Report
          </Button>
          <Button variant="outline" size="sm"
            disabled={enforce.isPending}
            onClick={() => enforce.mutate()}>
            <Zap className="w-4 h-4 mr-1.5" />
            {enforce.isPending ? "Enforcing…" : "Enforce Now"}
          </Button>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="w-4 h-4 mr-1.5" />Refresh
          </Button>
        </div>
      </div>

      {/* SLA Policy bar */}
      <Card className="bg-muted/30">
        <CardContent className="py-3 px-5">
          <div className="flex flex-wrap gap-5 items-center">
            <span className="text-sm font-medium text-muted-foreground">SLA Policy:</span>
            {Object.entries(SLA_POLICY).map(([sev, time]) => (
              <div key={sev} className="flex items-center gap-1.5 text-sm">
                <span className="w-2 h-2 rounded-full" style={{ background: SEV_COLOR[sev] }} />
                <span className="capitalize font-medium">{sev}:</span>
                <span className="text-muted-foreground">{time}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Summary cards */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {[
          { key: "total", label: "Total", value: data.total, color: "hsl(var(--foreground))" },
          { key: "on_track", label: "On Track", value: data.on_track, color: "#22c55e" },
          { key: "at_risk",  label: "At Risk",  value: data.at_risk,  color: "#eab308" },
          { key: "breached", label: "Breached", value: data.breached, color: "#ef4444" },
          { key: "resolved", label: "Resolved", value: data.resolved, color: "#94a3b8" },
        ].map(({ key, label, value, color }) => (
          <Card
            key={key}
            className={`cursor-pointer transition-all ${filter === key ? "ring-2 ring-primary" : ""}`}
            onClick={() => setFilter(filter === key ? "all" : key)}
          >
            <CardContent className="pt-5 pb-4">
              <p className="text-xs text-muted-foreground mb-1">{label}</p>
              <p className="text-3xl font-bold" style={{ color }}>{value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Compliance rate */}
      <Card>
        <CardContent className="py-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium">SLA Compliance Rate</span>
            <span className="text-2xl font-bold" style={{ color: scoreColor }}>{data.compliance_rate}%</span>
          </div>
          <Progress value={data.compliance_rate} className="h-2.5" />
          <p className="text-xs text-muted-foreground mt-1.5">
            {data.on_track + data.resolved} of {data.total} findings within SLA deadline
          </p>
        </CardContent>
      </Card>

      {/* Velocity metrics */}
      <Card>
        <CardHeader
          className="pb-2 cursor-pointer select-none"
          onClick={() => setShowVelocity(v => !v)}
        >
          <div className="flex items-center justify-between">
            <CardTitle className="text-base flex items-center gap-2">
              <TrendingDown className="w-4 h-4 text-primary" />
              Velocity Metrics — Average Time to Fix
            </CardTitle>
            {showVelocity ? <ChevronDown className="w-4 h-4 text-muted-foreground" /> : <ChevronRight className="w-4 h-4 text-muted-foreground" />}
          </div>
        </CardHeader>
        {showVelocity && (
          <CardContent>
            {velocity.filter(v => v.count > 0).length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-4">No resolved findings yet — velocity data will appear once findings are resolved.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-xs text-muted-foreground">
                      <th className="text-left py-2 pr-4">Severity</th>
                      <th className="text-right py-2 px-3">Avg Days</th>
                      <th className="text-right py-2 px-3">Target</th>
                      <th className="text-right py-2 px-3">vs Target</th>
                      <th className="text-right py-2 px-3">Within SLA</th>
                      <th className="py-2 pl-3 w-40">Progress</th>
                    </tr>
                  </thead>
                  <tbody>
                    {velocity.map(v => {
                      if (v.count === 0) return null;
                      const diff = v.avg_days !== null ? v.avg_days - v.target_days : null;
                      const slaRate = v.count > 0 ? Math.round((v.within_sla / v.count) * 100) : 0;
                      return (
                        <tr key={v.severity} className="border-t border-border">
                          <td className="py-2.5 pr-4">
                            <div className="flex items-center gap-2">
                              <span className="w-2.5 h-2.5 rounded-full" style={{ background: SEV_COLOR[v.severity] }} />
                              <span className="capitalize font-medium">{v.severity}</span>
                              <span className="text-xs text-muted-foreground">({v.count} resolved)</span>
                            </div>
                          </td>
                          <td className="py-2.5 px-3 text-right font-mono">
                            {v.avg_days !== null ? `${v.avg_days}d` : "—"}
                          </td>
                          <td className="py-2.5 px-3 text-right font-mono text-muted-foreground">{v.target_days}d</td>
                          <td className="py-2.5 px-3 text-right">
                            {diff !== null ? (
                              <span className={diff <= 0 ? "text-green-400 font-semibold" : "text-red-400 font-semibold"}>
                                {diff <= 0 ? `${Math.abs(diff)}d ahead` : `${diff}d over`}
                              </span>
                            ) : "—"}
                          </td>
                          <td className="py-2.5 px-3 text-right">{slaRate}%</td>
                          <td className="py-2.5 pl-3">
                            <Progress value={slaRate} className="h-1.5" />
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        )}
      </Card>

      {/* Burn-down chart */}
      <Card>
        <CardHeader
          className="pb-2 cursor-pointer select-none"
          onClick={() => setShowBurndown(v => !v)}
        >
          <div className="flex items-center justify-between">
            <CardTitle className="text-base flex items-center gap-2">
              <BarChart2 className="w-4 h-4 text-primary" />
              SLA Burn-Down — Last 6 Weeks
            </CardTitle>
            {showBurndown ? <ChevronDown className="w-4 h-4 text-muted-foreground" /> : <ChevronRight className="w-4 h-4 text-muted-foreground" />}
          </div>
        </CardHeader>
        {showBurndown && (
          <CardContent>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={burnDown} margin={{ top: 4, right: 16, bottom: 0, left: 0 }}>
                <XAxis dataKey="week" tick={{ fontSize: 11 }} />
                <YAxis tick={{ fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }}
                />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                <Bar dataKey="resolved"  name="Resolved"   stackId="a" fill="#94a3b8" radius={[0,0,0,0]} />
                <Bar dataKey="on_track"  name="On Track"   stackId="a" fill="#22c55e" radius={[0,0,0,0]} />
                <Bar dataKey="at_risk"   name="At Risk"    stackId="a" fill="#eab308" radius={[0,0,0,0]} />
                <Bar dataKey="breached"  name="Breached"   stackId="a" fill="#ef4444" radius={[4,4,0,0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        )}
      </Card>

      {/* Heatmap calendar */}
      <Card>
        <CardHeader
          className="pb-2 cursor-pointer select-none"
          onClick={() => setShowHeatmap(v => !v)}
        >
          <div className="flex items-center justify-between">
            <CardTitle className="text-base flex items-center gap-2">
              <CalendarDays className="w-4 h-4 text-primary" />
              SLA Breach Heatmap — Last 90 Days
            </CardTitle>
            {showHeatmap ? <ChevronDown className="w-4 h-4 text-muted-foreground" /> : <ChevronRight className="w-4 h-4 text-muted-foreground" />}
          </div>
        </CardHeader>
        {showHeatmap && (
          <CardContent>
            {Object.keys(heatmapData).length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-4">No SLA breaches in the last 90 days.</p>
            ) : (
              <HeatmapCalendar data={heatmapData} />
            )}
          </CardContent>
        )}
      </Card>

      {/* Exception requests */}
      {showExceptions && exceptions.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-yellow-400" />
              SLA Extension Requests
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {exceptions.map((ex: any) => (
              <div key={ex.id} className="flex items-start gap-3 p-3 rounded-lg border border-border">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="text-sm font-medium">{ex.finding_id}</span>
                    <Badge
                      variant="outline"
                      className={ex.status === "pending" ? "text-yellow-400 border-yellow-400/30 text-[10px]"
                        : ex.status === "approved" ? "text-green-400 border-green-400/30 text-[10px]"
                        : "text-red-400 border-red-400/30 text-[10px]"}
                    >
                      {ex.status}
                    </Badge>
                  </div>
                  <p className="text-xs text-muted-foreground">{ex.reason}</p>
                  <p className="text-[10px] text-muted-foreground mt-0.5">
                    By {ex.analyst} · +{ex.requested_days} days requested
                  </p>
                </div>
                {ex.status === "pending" && (
                  <div className="flex gap-1.5 flex-shrink-0">
                    <Button size="sm" variant="outline" className="h-7 text-xs text-green-400 border-green-400/30"
                      onClick={() => reviewException.mutate({ id: ex.id, status: "approved" })}>
                      Approve
                    </Button>
                    <Button size="sm" variant="outline" className="h-7 text-xs text-red-400 border-red-400/30"
                      onClick={() => reviewException.mutate({ id: ex.id, status: "denied" })}>
                      Deny
                    </Button>
                  </div>
                )}
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Findings table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            Findings by SLA Status
            <span className="ml-2 text-sm text-muted-foreground font-normal">
              {filter !== "all" ? `Filtered: ${filter.replace("_"," ")} · ` : ""}{filtered.length} finding(s)
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {filtered.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground text-sm">No findings match this filter.</div>
          ) : (
            <div className="divide-y divide-border">
              {filtered.map(f => {
                const cfg = STATUS_CFG[f.sla_status] ?? STATUS_CFG.on_track;
                const isBreached = f.sla_status === "breached";
                const dueDate = isValid(parseISO(f.sla_due)) ? parseISO(f.sla_due) : null;
                return (
                  <div key={f.id} className={`flex items-center gap-3 px-5 py-3 ${isBreached ? "bg-red-500/5" : ""}`}>
                    {cfg.icon}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-medium truncate">{f.title}</span>
                        <span
                          className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded"
                          style={{ background: `${SEV_COLOR[f.severity] ?? "#6b7280"}22`, color: SEV_COLOR[f.severity] ?? "#6b7280" }}
                        >
                          {f.severity}
                        </span>
                      </div>
                      <p className="text-xs text-muted-foreground font-mono truncate">{f.endpoint}</p>
                    </div>

                    {/* Countdown */}
                    <div className="text-right shrink-0">
                      <CountdownCell finding={f} />
                      {dueDate && (
                        <p className="text-[10px] text-muted-foreground mt-0.5">
                          Due {format(dueDate, "MMM d")}
                        </p>
                      )}
                    </div>

                    <Badge className={`${cfg.cls} border text-xs shrink-0`}>{cfg.label}</Badge>

                    <div className="flex gap-1 flex-shrink-0">
                      <Link href={`/findings/${f.id}`}>
                        <Button size="sm" variant="ghost" className="h-7 w-7 p-0">
                          <ExternalLink className="w-3.5 h-3.5" />
                        </Button>
                      </Link>
                      {(f.sla_status === "breached" || f.sla_status === "at_risk") && (
                        <Button size="sm" variant="ghost" className="h-7 w-7 p-0 text-yellow-400"
                          title="Request SLA extension"
                          onClick={() => setExceptionTarget(f)}>
                          <Plus className="w-3.5 h-3.5" />
                        </Button>
                      )}
                      {f.sla_status !== "resolved" && (
                        <Button size="sm" variant="outline" className="h-7 text-xs"
                          disabled={resolving === f.id}
                          onClick={() => handleResolve(f.id)}>
                          {resolving === f.id ? "…" : "Resolve"}
                        </Button>
                      )}
                      {/* 3-dot menu with Extend SLA */}
                      <div className="relative group">
                        <Button size="sm" variant="ghost" className="h-7 w-7 p-0"
                          onClick={() => setExtendTarget(extendTarget?.id === f.id ? null : f)}>
                          <MoreVertical className="w-3.5 h-3.5" />
                        </Button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Exception dialog */}
      {exceptionTarget && (
        <ExceptionDialog
          finding={exceptionTarget}
          onClose={() => setExceptionTarget(null)}
          onSubmit={(data) => createException.mutate(data)}
        />
      )}

      {/* SLA Extension dialog */}
      {extendTarget && (
        <SlaExtendDialog
          finding={extendTarget}
          onClose={() => setExtendTarget(null)}
          submitting={extendSla.isPending}
          onSubmit={(days, reason) =>
            extendSla.mutate({ id: extendTarget.id, days, reason })
          }
        />
      )}
    </div>
  );
}
