import { useState, useEffect } from "react";
import { Link } from "wouter";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { CheckCircle2, AlertTriangle, XCircle, Clock, RefreshCw, ExternalLink } from "lucide-react";
import { format, parseISO } from "date-fns";

interface SlaSummary {
  total: number; on_track: number; at_risk: number; breached: number; resolved: number;
  compliance_rate: number;
  findings: Array<{
    id: string; title: string; severity: string; endpoint: string;
    sla_due: string; sla_status: string; days_remaining: number;
  }>;
}

const STATUS_CONFIG: Record<string, { label: string; color: string; icon: React.ReactNode }> = {
  on_track: { label: "On Track", color: "text-emerald-400 bg-emerald-400/10 border-emerald-400/30", icon: <CheckCircle2 className="w-4 h-4 text-emerald-400" /> },
  at_risk: { label: "At Risk", color: "text-yellow-400 bg-yellow-400/10 border-yellow-400/30", icon: <AlertTriangle className="w-4 h-4 text-yellow-400" /> },
  breached: { label: "Breached", color: "text-red-400 bg-red-400/10 border-red-400/30", icon: <XCircle className="w-4 h-4 text-red-400" /> },
  resolved: { label: "Resolved", color: "text-slate-400 bg-slate-400/10 border-slate-400/30", icon: <CheckCircle2 className="w-4 h-4 text-slate-400" /> },
};

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-500 bg-red-500/10 border-red-500/30",
  high: "text-orange-500 bg-orange-500/10 border-orange-500/30",
  medium: "text-yellow-500 bg-yellow-500/10 border-yellow-500/30",
  low: "text-blue-400 bg-blue-400/10 border-blue-400/30",
  info: "text-slate-400 bg-slate-400/10 border-slate-400/30",
};

const SLA_POLICY: Record<string, string> = {
  critical: "1 business day", high: "7 business days", medium: "30 business days", low: "90 business days",
};

export default function SlaDashboard() {
  const [data, setData] = useState<SlaSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<string>("all");
  const [resolving, setResolving] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/sla/summary", { credentials: "include" });
      setData(await r.json());
    } catch { }
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const handleResolve = async (id: string) => {
    setResolving(id);
    try {
      await fetch(`/api/sla/finding/${id}/resolve`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ note: "Marked resolved via SLA dashboard" }),
      });
      await load();
    } catch { }
    setResolving(null);
  };

  const filtered = data?.findings.filter(f => filter === "all" || f.sla_status === filter) ?? [];

  if (loading) return <div className="flex items-center justify-center h-64 text-muted-foreground"><RefreshCw className="w-5 h-5 animate-spin mr-2" />Loading SLA data…</div>;
  if (!data) return null;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">SLA Tracking</h1>
          <p className="text-muted-foreground">Monitor remediation SLA compliance across all findings</p>
        </div>
        <Button variant="outline" onClick={load} className="gap-2"><RefreshCw className="w-4 h-4" />Refresh</Button>
      </div>

      {/* SLA Policy Reference */}
      <Card className="bg-muted/30">
        <CardContent className="pt-4 pb-4">
          <div className="flex flex-wrap gap-6">
            <span className="text-sm font-medium text-muted-foreground">SLA Policy:</span>
            {Object.entries(SLA_POLICY).map(([sev, time]) => (
              <div key={sev} className="flex items-center gap-1.5 text-sm">
                <span className={`w-2 h-2 rounded-full ${sev === "critical" ? "bg-red-500" : sev === "high" ? "bg-orange-500" : sev === "medium" ? "bg-yellow-500" : "bg-blue-400"}`} />
                <span className="capitalize font-medium">{sev}:</span>
                <span className="text-muted-foreground">{time}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {[
          { key: "total", label: "Total", value: data.total, color: "text-foreground" },
          { key: "on_track", label: "On Track", value: data.on_track, color: "text-emerald-400" },
          { key: "at_risk", label: "At Risk", value: data.at_risk, color: "text-yellow-400" },
          { key: "breached", label: "Breached", value: data.breached, color: "text-red-400" },
          { key: "resolved", label: "Resolved", value: data.resolved, color: "text-slate-400" },
        ].map(({ key, label, value, color }) => (
          <Card key={key} className={`cursor-pointer transition-all ${filter === key ? "ring-2 ring-primary" : ""}`} onClick={() => setFilter(filter === key ? "all" : key)}>
            <CardContent className="pt-6">
              <p className="text-xs text-muted-foreground mb-1">{label}</p>
              <p className={`text-3xl font-bold ${color}`}>{value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Compliance Rate */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">SLA Compliance Rate</CardTitle>
            <span className={`text-2xl font-bold ${data.compliance_rate >= 80 ? "text-emerald-400" : data.compliance_rate >= 60 ? "text-yellow-400" : "text-red-400"}`}>
              {data.compliance_rate}%
            </span>
          </div>
        </CardHeader>
        <CardContent>
          <Progress value={data.compliance_rate} className="h-3" />
          <p className="text-xs text-muted-foreground mt-2">
            {data.on_track + data.resolved} of {data.total} findings within SLA deadline
          </p>
        </CardContent>
      </Card>

      {/* Findings Table */}
      <Card>
        <CardHeader>
          <CardTitle>Findings by SLA Status</CardTitle>
          <CardDescription>
            {filter !== "all" ? `Filtered: ${filter.replace("_", " ")} · ` : ""}{filtered.length} finding(s)
          </CardDescription>
        </CardHeader>
        <CardContent>
          {filtered.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">No findings match this filter</div>
          ) : (
            <div className="space-y-2">
              {filtered.map(f => {
                const statusConf = STATUS_CONFIG[f.sla_status] ?? STATUS_CONFIG["on_track"];
                const isOverdue = f.sla_status === "breached";
                return (
                  <div key={f.id} className={`flex items-center gap-4 p-3 rounded-lg border bg-muted/30 ${isOverdue ? "border-red-500/20" : "border-border"}`}>
                    {statusConf.icon}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-medium truncate">{f.title}</span>
                        <Badge className={`${SEV_COLORS[f.severity]} border text-xs shrink-0`}>{f.severity}</Badge>
                      </div>
                      <p className="text-xs text-muted-foreground font-mono truncate">{f.endpoint}</p>
                    </div>
                    <div className="text-right shrink-0">
                      <div className="flex items-center gap-1 text-xs text-muted-foreground">
                        <Clock className="w-3 h-3" />
                        {f.sla_status === "resolved" ? "Resolved" : (
                          isOverdue
                            ? <span className="text-red-400 font-medium">{Math.abs(f.days_remaining)}d overdue</span>
                            : <span className={f.days_remaining <= 2 ? "text-yellow-400 font-medium" : ""}>{f.days_remaining}d left</span>
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground">Due {format(parseISO(f.sla_due), "MMM d")}</p>
                    </div>
                    <Badge className={`${statusConf.color} border text-xs shrink-0`}>{statusConf.label}</Badge>
                    <div className="flex gap-1">
                      <Link href={`/findings/${f.id}`}>
                        <Button size="sm" variant="ghost" className="h-7 w-7 p-0"><ExternalLink className="w-3 h-3" /></Button>
                      </Link>
                      {f.sla_status !== "resolved" && (
                        <Button
                          size="sm" variant="outline" className="h-7 text-xs"
                          onClick={() => handleResolve(f.id)}
                          disabled={resolving === f.id}
                        >
                          {resolving === f.id ? "..." : "Resolve"}
                        </Button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
