import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ArrowRight, TrendingDown, TrendingUp, Minus, AlertTriangle, CheckCircle, Plus, RefreshCw } from "lucide-react";
import { format } from "date-fns";

interface ScanJob {
  id: string; target_url: string; created_at: string; status: string;
  risk_score: number; findings_count: number;
}

interface ComparisonResult {
  scan_a: { id: string; target_url: string; created_at: string; risk_score: number; findings_count: number };
  scan_b: { id: string; target_url: string; created_at: string; risk_score: number; findings_count: number };
  summary: { risk_delta: number; risk_trend: string; new_findings_count: number; resolved_findings_count: number; persisted_findings_count: number };
  severity_breakdown: {
    a: { critical: number; high: number; medium: number; low: number };
    b: { critical: number; high: number; medium: number; low: number };
  };
  new_findings: Array<{ id: string; title: string; severity: string; endpoint: string; cvss_score: number }>;
  resolved_findings: Array<{ id: string; title: string; severity: string; endpoint: string; cvss_score: number }>;
  persisted_findings: Array<{ id: string; title: string; severity: string; endpoint: string }>;
}

const SEV_COLORS: Record<string, string> = {
  critical: "text-red-500 bg-red-500/10 border-red-500/30",
  high: "text-orange-500 bg-orange-500/10 border-orange-500/30",
  medium: "text-yellow-500 bg-yellow-500/10 border-yellow-500/30",
  low: "text-blue-400 bg-blue-400/10 border-blue-400/30",
  info: "text-slate-400 bg-slate-400/10 border-slate-400/30",
};

export default function ScanCompare() {
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [scanA, setScanA] = useState("");
  const [scanB, setScanB] = useState("");
  const [result, setResult] = useState<ComparisonResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/scan-jobs?page_size=50", { credentials: "include" })
      .then(r => r.json())
      .then(data => setScans(data.items?.filter((s: ScanJob) => s.status === "completed") ?? []))
      .catch(() => {});
  }, []);

  const compare = async () => {
    if (!scanA || !scanB) return;
    setLoading(true); setError(null); setResult(null);
    try {
      const r = await fetch("/api/scan-jobs/compare", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scan_id_a: scanA, scan_id_b: scanB }),
      });
      if (!r.ok) throw new Error("Comparison failed");
      setResult(await r.json());
    } catch (e) {
      setError("Failed to compare scans. Please try again.");
    }
    setLoading(false);
  };

  const formatScanLabel = (s: ScanJob) =>
    `${s.target_url.replace(/https?:\/\//, "").slice(0, 30)} — ${format(new Date(s.created_at), "MMM d, HH:mm")} (${s.findings_count} findings)`;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Scan Comparison</h1>
        <p className="text-muted-foreground">Compare two scans to see what's improved or regressed</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Select Scans to Compare</CardTitle>
          <CardDescription>Choose two completed scans — Scan B is usually the more recent one</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-4 flex-wrap">
            <div className="flex-1 min-w-48">
              <p className="text-sm font-medium mb-1.5 text-muted-foreground">Baseline (Older)</p>
              <Select value={scanA} onValueChange={setScanA}>
                <SelectTrigger>
                  <SelectValue placeholder="Select scan A..." />
                </SelectTrigger>
                <SelectContent>
                  {scans.map(s => (
                    <SelectItem key={s.id} value={s.id}>{formatScanLabel(s)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <ArrowRight className="w-5 h-5 text-muted-foreground shrink-0 mt-5" />
            <div className="flex-1 min-w-48">
              <p className="text-sm font-medium mb-1.5 text-muted-foreground">Comparison (Newer)</p>
              <Select value={scanB} onValueChange={setScanB}>
                <SelectTrigger>
                  <SelectValue placeholder="Select scan B..." />
                </SelectTrigger>
                <SelectContent>
                  {scans.map(s => (
                    <SelectItem key={s.id} value={s.id}>{formatScanLabel(s)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Button onClick={compare} disabled={!scanA || !scanB || loading} className="mt-5 gap-2">
              <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
              {loading ? "Comparing..." : "Compare"}
            </Button>
          </div>
          {error && <p className="text-sm text-destructive mt-3">{error}</p>}
        </CardContent>
      </Card>

      {result && (
        <div className="space-y-4">
          {/* Summary Banner */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              {
                label: "Risk Delta",
                value: result.summary.risk_delta > 0 ? `+${result.summary.risk_delta}` : result.summary.risk_delta.toString(),
                icon: result.summary.risk_trend === "improved" ? <TrendingDown className="w-5 h-5 text-emerald-500" /> : result.summary.risk_trend === "worse" ? <TrendingUp className="w-5 h-5 text-red-500" /> : <Minus className="w-5 h-5 text-slate-400" />,
                color: result.summary.risk_trend === "improved" ? "text-emerald-500" : result.summary.risk_trend === "worse" ? "text-red-500" : "text-slate-400",
              },
              { label: "New Findings", value: result.summary.new_findings_count, icon: <Plus className="w-5 h-5 text-red-400" />, color: "text-red-400" },
              { label: "Resolved", value: result.summary.resolved_findings_count, icon: <CheckCircle className="w-5 h-5 text-emerald-400" />, color: "text-emerald-400" },
              { label: "Persisted", value: result.summary.persisted_findings_count, icon: <AlertTriangle className="w-5 h-5 text-yellow-400" />, color: "text-yellow-400" },
            ].map(({ label, value, icon, color }) => (
              <Card key={label}>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between mb-2">{icon}<span className="text-xs text-muted-foreground">{label}</span></div>
                  <p className={`text-3xl font-bold ${color}`}>{value}</p>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Severity Breakdown */}
          <Card>
            <CardHeader><CardTitle className="text-base">Severity Breakdown</CardTitle></CardHeader>
            <CardContent>
              <div className="grid grid-cols-4 gap-4">
                {(["critical", "high", "medium", "low"] as const).map(sev => {
                  const a = result.severity_breakdown.a[sev] ?? 0;
                  const b = result.severity_breakdown.b[sev] ?? 0;
                  const delta = b - a;
                  return (
                    <div key={sev} className="text-center">
                      <p className={`text-xs uppercase font-semibold mb-2 ${SEV_COLORS[sev].split(" ")[0]}`}>{sev}</p>
                      <div className="flex items-center justify-center gap-2 text-lg font-bold">
                        <span className="text-muted-foreground">{a}</span>
                        <ArrowRight className="w-3 h-3 text-muted-foreground" />
                        <span>{b}</span>
                      </div>
                      {delta !== 0 && (
                        <p className={`text-xs mt-1 ${delta > 0 ? "text-red-400" : "text-emerald-400"}`}>
                          {delta > 0 ? "+" : ""}{delta}
                        </p>
                      )}
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* New Findings */}
          {result.new_findings.length > 0 && (
            <Card className="border-red-500/20">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-red-400">
                  <Plus className="w-4 h-4" /> New Findings ({result.new_findings.length})
                </CardTitle>
                <CardDescription>Vulnerabilities that appeared in the new scan</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {result.new_findings.map(f => (
                    <div key={f.id} className="flex items-center justify-between p-3 rounded-lg bg-muted/50 border border-border">
                      <div>
                        <p className="text-sm font-medium">{f.title}</p>
                        <p className="text-xs text-muted-foreground font-mono">{f.endpoint}</p>
                      </div>
                      <Badge className={`${SEV_COLORS[f.severity]} border shrink-0`}>{f.severity}</Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Resolved Findings */}
          {result.resolved_findings.length > 0 && (
            <Card className="border-emerald-500/20">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-emerald-400">
                  <CheckCircle className="w-4 h-4" /> Resolved Findings ({result.resolved_findings.length})
                </CardTitle>
                <CardDescription>Vulnerabilities no longer detected in the new scan</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {result.resolved_findings.map(f => (
                    <div key={f.id} className="flex items-center justify-between p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/20">
                      <div>
                        <p className="text-sm font-medium line-through text-muted-foreground">{f.title}</p>
                        <p className="text-xs text-muted-foreground font-mono">{f.endpoint}</p>
                      </div>
                      <Badge variant="outline" className="text-emerald-400 border-emerald-500/30 shrink-0">{f.severity}</Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}
