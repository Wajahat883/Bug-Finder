import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { CheckCircle2, XCircle, Shield, AlertTriangle, ExternalLink, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";

interface OwaspItem {
  id: string; name: string; url: string; status: string;
  findings_count: number; critical: number; high: number;
}
interface FrameworkResult {
  score: number; status: string; issues?: Array<{ req: string; finding_title: string; severity: string }>;
  notes?: string;
}
interface ComplianceReport {
  generated_at: string; total_findings: number;
  owasp_top10: OwaspItem[];
  owasp_compliance_score: number;
  pci_dss: FrameworkResult;
  soc2: FrameworkResult;
  iso27001: FrameworkResult;
  hipaa: FrameworkResult;
}

export default function ComplianceDashboard() {
  const [report, setReport] = useState<ComplianceReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const r = await fetch("/api/compliance/report", { credentials: "include" });
      if (!r.ok) throw new Error("Failed");
      setReport(await r.json());
    } catch {
      setError("Failed to load compliance report");
    }
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  if (loading) return <div className="flex items-center justify-center h-64 text-muted-foreground"><RefreshCw className="w-5 h-5 animate-spin mr-2" /> Loading compliance data…</div>;
  if (error) return <div className="text-center py-20 text-destructive">{error}</div>;
  if (!report) return null;

  const frameworks = [
    { key: "pci_dss", name: "PCI DSS 4.0", color: "blue", data: report.pci_dss },
    { key: "soc2", name: "SOC 2 Type II", color: "purple", data: report.soc2 },
    { key: "iso27001", name: "ISO 27001:2022", color: "green", data: report.iso27001 },
    { key: "hipaa", name: "HIPAA Security", color: "orange", data: report.hipaa },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Compliance Dashboard</h1>
          <p className="text-muted-foreground">Security posture against major compliance frameworks</p>
        </div>
        <Button variant="outline" onClick={load} className="gap-2">
          <RefreshCw className="w-4 h-4" /> Refresh
        </Button>
      </div>

      {/* Framework Scores */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        {frameworks.map(({ key, name, data }) => (
          <Card key={key} className={data.status === "compliant" ? "border-emerald-500/20" : "border-orange-500/20"}>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-medium">{name}</CardTitle>
                <Badge className={data.status === "compliant" ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" : "bg-orange-500/20 text-orange-400 border-orange-500/30"}>
                  {data.status === "compliant" ? "Compliant" : "At Risk"}
                </Badge>
              </div>
            </CardHeader>
            <CardContent>
              <p className={`text-3xl font-bold mb-2 ${data.score >= 80 ? "text-emerald-400" : data.score >= 60 ? "text-yellow-400" : "text-red-400"}`}>
                {data.score}<span className="text-base text-muted-foreground">/100</span>
              </p>
              <Progress value={data.score} className="h-2" />
            </CardContent>
          </Card>
        ))}
      </div>

      {/* OWASP Top 10 */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle>OWASP Top 10 — 2021</CardTitle>
            <CardDescription>
              {report.owasp_top10.filter(o => o.status === "pass").length}/10 categories passed ·
              Compliance score: {report.owasp_compliance_score}%
            </CardDescription>
          </div>
          <div className={`text-2xl font-bold ${report.owasp_compliance_score >= 80 ? "text-emerald-400" : report.owasp_compliance_score >= 50 ? "text-yellow-400" : "text-red-400"}`}>
            {report.owasp_compliance_score}%
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {report.owasp_top10.map(item => (
              <div key={item.id} className={`flex items-center justify-between p-3 rounded-lg border ${item.status === "pass" ? "bg-emerald-500/5 border-emerald-500/20" : "bg-red-500/5 border-red-500/20"}`}>
                <div className="flex items-center gap-3">
                  {item.status === "pass"
                    ? <CheckCircle2 className="w-5 h-5 text-emerald-500 shrink-0" />
                    : <XCircle className="w-5 h-5 text-red-500 shrink-0" />}
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-muted-foreground">{item.id}</span>
                      <span className="text-sm font-medium">{item.name}</span>
                    </div>
                    {item.status === "fail" && (
                      <p className="text-xs text-muted-foreground mt-0.5">
                        {item.findings_count} finding(s)
                        {item.critical > 0 && <span className="text-red-400 ml-1">· {item.critical} critical</span>}
                        {item.high > 0 && <span className="text-orange-400 ml-1">· {item.high} high</span>}
                      </p>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant={item.status === "pass" ? "outline" : "destructive"} className="text-xs">
                    {item.status === "pass" ? "PASS" : "FAIL"}
                  </Badge>
                  <a href={item.url} target="_blank" rel="noopener noreferrer" className="text-muted-foreground hover:text-foreground">
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Framework Details */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {frameworks.filter(f => (f.data.issues?.length ?? 0) > 0).map(({ name, data }) => (
          <Card key={name}>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-orange-400" />
                {name} Issues
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 max-h-64 overflow-y-auto">
                {data.issues?.slice(0, 10).map((issue, i) => (
                  <div key={i} className="flex items-start gap-2 text-sm">
                    <XCircle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
                    <div>
                      <p className="font-medium text-xs text-muted-foreground">{issue.req}</p>
                      <p className="text-xs">{issue.finding_title}</p>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <p className="text-xs text-center text-muted-foreground">
        Generated {new Date(report.generated_at).toLocaleString()} · Based on {report.total_findings} total findings ·
        <span className="ml-1">Compliance scores are estimates based on discovered vulnerabilities and should supplement, not replace, official assessments</span>
      </p>
    </div>
  );
}
