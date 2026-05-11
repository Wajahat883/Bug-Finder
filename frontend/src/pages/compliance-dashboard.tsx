import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer,
} from "recharts";
import {
  Shield, CheckCircle2, XCircle, AlertTriangle, Download,
  RefreshCw, Plus, Trash2, ChevronDown, ChevronRight, ExternalLink,
} from "lucide-react";

// ── Framework control definitions ─────────────────────────────────────────

const FRAMEWORK_CONTROLS: Record<string, Array<{ id: string; name: string; categories: string[] }>> = {
  pci_dss: [
    { id: "6.2.4", name: "Prevent common software attacks (Injection, XSS)", categories: ["Injection","XSS","Cross-Site Scripting","Template Injection","SQLi"] },
    { id: "4.2.1", name: "Strong cryptography for data in transit", categories: ["TLS","Cryptographic"] },
    { id: "3.5",   name: "Protect stored account / cardholder data", categories: ["Secrets Exposure"] },
    { id: "8",     name: "Identify users and authenticate access", categories: ["Authentication","JWT Security","Session Management"] },
    { id: "6.3",   name: "Address security vulnerabilities in software", categories: ["Known Vulnerability","Supply Chain"] },
    { id: "6.3.3", name: "All components protected from known vulnerabilities", categories: ["Known Vulnerability","Supply Chain"] },
    { id: "7",     name: "Restrict access to system components", categories: ["Broken Access Control","IDOR","Path Traversal"] },
  ],
  soc2: [
    { id: "CC6.1", name: "Logical and physical access controls", categories: ["Authentication","Broken Access Control","IDOR"] },
    { id: "CC6.6", name: "Restrict logical access to restricted assets", categories: ["Security Misconfiguration","Information Disclosure"] },
    { id: "CC6.7", name: "Data transmission security", categories: ["TLS","Cryptographic","Secrets Exposure"] },
    { id: "CC7.1", name: "Detection and monitoring of threats", categories: ["Known Vulnerability"] },
    { id: "CC8.1", name: "Change management controls", categories: ["Supply Chain"] },
  ],
  hipaa: [
    { id: "§164.312(a)(1)", name: "Access controls for ePHI systems", categories: ["Authentication","Broken Access Control","IDOR"] },
    { id: "§164.312(e)(1)", name: "Transmission security for ePHI", categories: ["TLS","Cryptographic"] },
    { id: "§164.312(a)(2)", name: "Automatic logoff and encryption", categories: ["Session Management","JWT Security"] },
    { id: "§164.308(a)(1)", name: "Security management process", categories: ["Known Vulnerability","Supply Chain"] },
  ],
  iso27001: [
    { id: "A.9",  name: "Access control", categories: ["Authentication","Broken Access Control","IDOR"] },
    { id: "A.10", name: "Cryptography", categories: ["TLS","Cryptographic","Secrets Exposure"] },
    { id: "A.12", name: "Operations security", categories: ["Security Misconfiguration","Known Vulnerability"] },
    { id: "A.14", name: "System acquisition and development", categories: ["Injection","XSS","File Upload"] },
    { id: "A.18", name: "Compliance", categories: [] },
  ],
};

const FRAMEWORK_META: Record<string, { name: string; color: string }> = {
  pci_dss:  { name: "PCI DSS 4.0",    color: "#3b82f6" },
  soc2:     { name: "SOC 2 Type II",  color: "#a855f7" },
  hipaa:    { name: "HIPAA Security", color: "#f97316" },
  iso27001: { name: "ISO 27001:2022", color: "#22c55e" },
};

// ── Score badge ───────────────────────────────────────────────────────────

function ScoreBadge({ score }: { score: number }) {
  const color = score >= 80 ? "#22c55e" : score >= 60 ? "#eab308" : "#ef4444";
  return (
    <span className="text-3xl font-bold" style={{ color }}>
      {score}<span className="text-base text-muted-foreground">/100</span>
    </span>
  );
}

// ── Attestation dialog ────────────────────────────────────────────────────

function AttestDialog({
  framework,
  control,
  onClose,
  onCreate,
}: {
  framework: string;
  control: { id: string; name: string };
  onClose: () => void;
  onCreate: (data: { framework: string; control_id: string; control_name: string; note: string; analyst: string }) => void;
}) {
  const [note, setNote] = useState("");
  const [analyst, setAnalyst] = useState("");
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div className="bg-card border border-border rounded-xl shadow-2xl p-6 w-full max-w-md" onClick={e => e.stopPropagation()}>
        <h3 className="font-semibold mb-1">Manual Attestation</h3>
        <p className="text-xs text-muted-foreground mb-4">
          Mark <strong>{control.id}</strong> — {control.name} as manually reviewed and compliant.
        </p>
        <div className="space-y-3">
          <div>
            <Label className="text-xs mb-1">Analyst Name</Label>
            <Input value={analyst} onChange={e => setAnalyst(e.target.value)} placeholder="John Smith" className="h-8 text-sm" />
          </div>
          <div>
            <Label className="text-xs mb-1">Review Note</Label>
            <textarea
              value={note}
              onChange={e => setNote(e.target.value)}
              placeholder="Describe the review performed and evidence examined..."
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm resize-none h-24"
            />
          </div>
        </div>
        <div className="flex justify-end gap-2 mt-4">
          <Button variant="ghost" size="sm" onClick={onClose}>Cancel</Button>
          <Button size="sm" onClick={() => onCreate({ framework, control_id: control.id, control_name: control.name, note, analyst })}>
            <CheckCircle2 className="w-4 h-4 mr-1.5" /> Attest
          </Button>
        </div>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────

export default function ComplianceDashboard() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [activeFramework, setActiveFramework] = useState("pci_dss");
  const [expandedControl, setExpandedControl] = useState<string | null>(null);
  const [attestTarget, setAttestTarget] = useState<{ framework: string; control: { id: string; name: string } } | null>(null);

  const { data: report, isLoading, refetch } = useQuery<any>({
    queryKey: ["/api/compliance/report"],
    queryFn: () => fetch("/api/compliance/report", { credentials: "include" }).then(r => r.json()),
  });

  const { data: history = [] } = useQuery<any[]>({
    queryKey: ["/api/compliance/history"],
    queryFn: () => fetch("/api/compliance/history", { credentials: "include" }).then(r => r.json()),
  });

  const { data: attestations = [] } = useQuery<any[]>({
    queryKey: ["/api/compliance/attestations"],
    queryFn: () => fetch("/api/compliance/attestations", { credentials: "include" }).then(r => r.json()),
  });

  const { data: allFindings = [] } = useQuery<any[]>({
    queryKey: ["/api/findings", "compliance"],
    queryFn: () => fetch("/api/findings?limit=500", { credentials: "include" }).then(r => r.json()).then(d => Array.isArray(d) ? d : d?.items ?? []),
  });

  const createAttestation = useMutation({
    mutationFn: (body: object) =>
      fetch("/api/compliance/attestations", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/compliance/attestations"] });
      toast({ title: "Attestation recorded" });
      setAttestTarget(null);
    },
  });

  const deleteAttestation = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/compliance/attestations/${id}`, { method: "DELETE", credentials: "include" }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/compliance/attestations"] });
      toast({ title: "Attestation removed" });
    },
  });

  function exportAuditPack(fw: string) {
    window.open(`/api/compliance/export/${fw}`, "_blank");
  }

  if (isLoading) return (
    <div className="flex items-center justify-center h-64 text-muted-foreground">
      <RefreshCw className="w-5 h-5 animate-spin mr-2" /> Loading compliance data…
    </div>
  );

  if (!report) return null;

  const frameworks = [
    { key: "pci_dss",  data: report.pci_dss },
    { key: "soc2",     data: report.soc2 },
    { key: "hipaa",    data: report.hipaa },
    { key: "iso27001", data: report.iso27001 },
  ];

  // Control-level pass/fail for active framework
  const controls = FRAMEWORK_CONTROLS[activeFramework] ?? [];
  const frameworkAttestations = attestations.filter((a: any) => a.framework === activeFramework);
  const attestedControlIds = new Set(frameworkAttestations.map((a: any) => a.control_id));

  // Per-control status based on whether any finding matches its categories
  const controlStatus = controls.map(ctrl => {
    const matchingFindings = allFindings.filter(f => ctrl.categories.includes(f.category ?? ""));
    const attested = attestedControlIds.has(ctrl.id);
    const hasCritHigh = matchingFindings.some(f => f.severity === "critical" || f.severity === "high");
    let status: "pass" | "fail" | "warning" | "attested" | "untested";
    if (ctrl.categories.length === 0) status = "untested";
    else if (attested && matchingFindings.length === 0) status = "attested";
    else if (matchingFindings.length === 0) status = "pass";
    else if (hasCritHigh) status = "fail";
    else status = "warning";
    return { ...ctrl, findings: matchingFindings, status, attested };
  });

  // Gap analysis: untested controls (no scanner coverage + not attested)
  const gaps = controlStatus.filter(c => c.status === "untested" || (c.findings.length === 0 && !c.attested && c.categories.length > 0));

  // Multi-target rollup
  const targetGroups = allFindings.reduce((acc: Record<string, number>, f: any) => {
    const t = f.target_url ?? "Unknown";
    acc[t] = (acc[t] ?? 0) + 1;
    return acc;
  }, {});

  const statusIcon = (s: string) => ({
    pass:     <CheckCircle2 className="w-4 h-4 text-green-400" />,
    fail:     <XCircle className="w-4 h-4 text-red-400" />,
    warning:  <AlertTriangle className="w-4 h-4 text-yellow-400" />,
    attested: <CheckCircle2 className="w-4 h-4 text-blue-400" />,
    untested: <AlertTriangle className="w-4 h-4 text-muted-foreground" />,
  }[s] ?? null);

  const statusLabel = (s: string) => ({
    pass: { label: "Pass", cls: "text-green-400 bg-green-400/10 border-green-400/20" },
    fail: { label: "Fail", cls: "text-red-400 bg-red-400/10 border-red-400/20" },
    warning: { label: "Warning", cls: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20" },
    attested: { label: "Attested", cls: "text-blue-400 bg-blue-400/10 border-blue-400/20" },
    untested: { label: "Untested", cls: "text-muted-foreground bg-muted/40 border-border" },
  }[s] ?? { label: s, cls: "" });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
            <Shield className="w-7 h-7" />
            Compliance Dashboard
          </h1>
          <p className="text-muted-foreground mt-1">
            Control-level pass/fail, gap analysis, attestations, and audit exports.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="w-4 h-4 mr-1.5" />Refresh
          </Button>
          <Button variant="outline" size="sm" onClick={() => exportAuditPack(activeFramework)}>
            <Download className="w-4 h-4 mr-1.5" />Export Audit Pack
          </Button>
        </div>
      </div>

      {/* Framework score cards */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        {frameworks.map(({ key, data }) => {
          const meta = FRAMEWORK_META[key];
          const isActive = activeFramework === key;
          return (
            <Card
              key={key}
              className={`cursor-pointer transition-all ${isActive ? "ring-2 ring-primary" : "hover:border-primary/30"}`}
              onClick={() => setActiveFramework(key)}
            >
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-sm font-medium">{meta.name}</span>
                  <Badge
                    variant="outline"
                    className={data?.status === "compliant"
                      ? "text-green-400 border-green-400/30 bg-green-400/10 text-xs"
                      : "text-orange-400 border-orange-400/30 bg-orange-400/10 text-xs"}
                  >
                    {data?.status === "compliant" ? "Compliant" : "At Risk"}
                  </Badge>
                </div>
                <ScoreBadge score={data?.score ?? 0} />
                <Progress value={data?.score ?? 0} className="h-1.5 mt-2" />
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Compliance Score Timeline */}
      {history.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Score Timeline — Last 8 Weeks</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={180}>
              <LineChart data={history} margin={{ top: 4, right: 16, bottom: 0, left: 0 }}>
                <XAxis dataKey="week" tick={{ fontSize: 11 }} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }}
                />
                <Legend wrapperStyle={{ fontSize: 12 }} />
                <Line type="monotone" dataKey="pci"  stroke="#3b82f6" strokeWidth={2} dot={false} name="PCI DSS" />
                <Line type="monotone" dataKey="soc2" stroke="#a855f7" strokeWidth={2} dot={false} name="SOC 2" />
                <Line type="monotone" dataKey="owasp" stroke="#22c55e" strokeWidth={2} dot={false} name="OWASP" />
                <Line type="monotone" dataKey="iso"  stroke="#f97316" strokeWidth={2} dot={false} name="ISO 27001" />
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      )}

      {/* Multi-target rollup */}
      {Object.keys(targetGroups).length > 1 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Multi-Target Finding Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {Object.entries(targetGroups)
                .sort(([, a], [, b]) => (b as number) - (a as number))
                .slice(0, 8)
                .map(([target, count]) => (
                  <div key={target} className="flex items-center gap-3 text-sm">
                    <span className="font-mono text-xs text-muted-foreground truncate w-64">{target}</span>
                    <div className="flex-1">
                      <Progress value={Math.min(100, ((count as number) / allFindings.length) * 100)} className="h-2" />
                    </div>
                    <span className="text-xs text-muted-foreground w-8 text-right">{count as number}</span>
                  </div>
                ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Control-level table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-base">
                {FRAMEWORK_META[activeFramework]?.name} — Control Status
              </CardTitle>
              <p className="text-xs text-muted-foreground mt-0.5">
                {controlStatus.filter(c => c.status === "pass" || c.status === "attested").length}/{controls.length} controls passing
              </p>
            </div>
            <Button size="sm" variant="outline" onClick={() => exportAuditPack(activeFramework)}>
              <Download className="w-3.5 h-3.5 mr-1.5" />Export
            </Button>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="divide-y divide-border">
            {controlStatus.map(ctrl => {
              const sl = statusLabel(ctrl.status);
              const isOpen = expandedControl === ctrl.id;
              return (
                <div key={ctrl.id}>
                  <div
                    className="flex items-center gap-3 px-5 py-3 hover:bg-accent/20 cursor-pointer transition-colors"
                    onClick={() => setExpandedControl(isOpen ? null : ctrl.id)}
                  >
                    {statusIcon(ctrl.status)}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs text-muted-foreground">{ctrl.id}</span>
                        <span className="text-sm font-medium">{ctrl.name}</span>
                        {ctrl.attested && (
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-blue-400/15 text-blue-400 font-medium">Attested</span>
                        )}
                      </div>
                      {ctrl.findings.length > 0 && (
                        <p className="text-xs text-muted-foreground mt-0.5">
                          {ctrl.findings.length} finding(s) ·{" "}
                          {ctrl.findings.filter((f: any) => f.severity === "critical").length > 0 && (
                            <span className="text-red-400">{ctrl.findings.filter((f: any) => f.severity === "critical").length} critical</span>
                          )}
                        </p>
                      )}
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${sl.cls}`}>
                        {sl.label}
                      </Badge>
                      {(ctrl.status === "untested" || ctrl.status === "pass") && !ctrl.attested && (
                        <Button
                          size="sm" variant="ghost" className="h-6 text-[10px] px-2"
                          onClick={e => { e.stopPropagation(); setAttestTarget({ framework: activeFramework, control: { id: ctrl.id, name: ctrl.name } }); }}
                        >
                          <Plus className="w-3 h-3 mr-1" />Attest
                        </Button>
                      )}
                      {isOpen ? <ChevronDown className="w-4 h-4 text-muted-foreground" /> : <ChevronRight className="w-4 h-4 text-muted-foreground" />}
                    </div>
                  </div>

                  {isOpen && ctrl.findings.length > 0 && (
                    <div className="px-5 pb-3 bg-accent/10 space-y-1.5">
                      {ctrl.findings.slice(0, 5).map((f: any) => (
                        <div key={f.id ?? f._id} className="flex items-center gap-2 text-xs">
                          <span
                            className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase"
                            style={{ background: `${({ critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22d3ee" }[f.severity as string] ?? "#6b7280")}22`, color: ({ critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22d3ee" }[f.severity as string] ?? "#6b7280") }}
                          >
                            {f.severity}
                          </span>
                          <span className="font-medium">{f.title}</span>
                          <span className="text-muted-foreground font-mono">{f.endpoint}</span>
                        </div>
                      ))}
                      {ctrl.findings.length > 5 && (
                        <p className="text-xs text-muted-foreground">+{ctrl.findings.length - 5} more</p>
                      )}
                    </div>
                  )}

                  {isOpen && ctrl.attested && (
                    <div className="px-5 pb-3 bg-blue-400/5">
                      {frameworkAttestations.filter((a: any) => a.control_id === ctrl.id).map((a: any) => (
                        <div key={a.id} className="flex items-start justify-between text-xs text-muted-foreground">
                          <div>
                            <span className="font-medium text-blue-400">Attested by {a.analyst}</span>
                            {a.note && <p className="mt-0.5">{a.note}</p>}
                          </div>
                          <Button variant="ghost" size="icon" className="h-6 w-6 text-destructive"
                            onClick={() => deleteAttestation.mutate(a.id)}>
                            <Trash2 className="w-3 h-3" />
                          </Button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Gap analysis */}
      {gaps.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-yellow-400" />
              Gap Analysis — Untested Controls
            </CardTitle>
            <p className="text-xs text-muted-foreground">
              These controls have no scanner coverage AND no manual attestation. Schedule scans or attest them.
            </p>
          </CardHeader>
          <CardContent className="space-y-2">
            {gaps.map(ctrl => (
              <div key={ctrl.id} className="flex items-center justify-between px-3 py-2 rounded-lg border border-yellow-500/20 bg-yellow-500/5">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 text-yellow-400" />
                  <span className="font-mono text-xs text-muted-foreground">{ctrl.id}</span>
                  <span className="text-sm">{ctrl.name}</span>
                </div>
                <Button
                  size="sm" variant="ghost" className="h-6 text-[10px] px-2 text-yellow-400 hover:text-yellow-300"
                  onClick={() => setAttestTarget({ framework: activeFramework, control: { id: ctrl.id, name: ctrl.name } })}
                >
                  <Plus className="w-3 h-3 mr-1" />Attest
                </Button>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Attestation dialog */}
      {attestTarget && (
        <AttestDialog
          framework={attestTarget.framework}
          control={attestTarget.control}
          onClose={() => setAttestTarget(null)}
          onCreate={(data) => createAttestation.mutate(data)}
        />
      )}

      <p className="text-xs text-center text-muted-foreground">
        Compliance scores are estimates based on discovered vulnerabilities and should supplement, not replace, official audits.
      </p>
    </div>
  );
}
