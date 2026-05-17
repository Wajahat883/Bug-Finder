import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, useRef } from "react";
import { Link } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer,
} from "recharts";
import {
  Shield, CheckCircle2, XCircle, AlertTriangle, Download,
  RefreshCw, Plus, Trash2, ChevronDown, ChevronRight, ExternalLink, X,
  Upload, CheckSquare,
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

const FRAMEWORK_META: Record<string, { name: string; color: string; tabLabel: string }> = {
  pci_dss:  { name: "PCI DSS 4.0",    color: "#3b82f6", tabLabel: "PCI-DSS" },
  soc2:     { name: "SOC 2 Type II",  color: "#a855f7", tabLabel: "SOC2" },
  hipaa:    { name: "HIPAA Security", color: "#f97316", tabLabel: "HIPAA" },
  iso27001: { name: "ISO 27001:2022", color: "#22c55e", tabLabel: "ISO 27001" },
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

// ── Circular Score Badge ──────────────────────────────────────────────────

function CircularScore({ score, size = 64 }: { score: number; size?: number }) {
  const color = score >= 80 ? "#22c55e" : score >= 60 ? "#eab308" : "#ef4444";
  const radius = (size - 8) / 2;
  const circ = 2 * Math.PI * radius;
  const dash = (score / 100) * circ;
  return (
    <svg width={size} height={size} className="rotate-[-90deg]">
      <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="hsl(var(--border))" strokeWidth={6} />
      <circle
        cx={size / 2} cy={size / 2} r={radius}
        fill="none" stroke={color} strokeWidth={6}
        strokeDasharray={`${dash} ${circ - dash}`}
        strokeLinecap="round"
      />
      <text
        x={size / 2} y={size / 2 + 5}
        textAnchor="middle"
        fontSize={13}
        fontWeight="bold"
        fill={color}
        style={{ transform: `rotate(90deg)`, transformOrigin: `${size / 2}px ${size / 2}px` }}
      >
        {score}%
      </text>
    </svg>
  );
}

// ── Framework Selector Tabs ───────────────────────────────────────────────

interface FrameworkTabsProps {
  active: string;
  onChange: (key: string) => void;
  report: Record<string, any>;
  controlStatuses: Record<string, Array<{ status: string }>>;
  onExportAttestation: (fw: string) => void;
}

function FrameworkTabs({ active, onChange, report, controlStatuses, onExportAttestation }: FrameworkTabsProps) {
  const fwKeys = ["soc2", "iso27001", "pci_dss", "hipaa"];
  return (
    <div className="border rounded-lg overflow-hidden">
      {/* Tab headers */}
      <div className="flex border-b border-border bg-muted/30">
        {fwKeys.map((key) => {
          const meta = FRAMEWORK_META[key];
          const isActive = active === key;
          return (
            <button
              key={key}
              onClick={() => onChange(key)}
              className={`flex-1 px-4 py-2.5 text-sm font-medium transition-colors border-b-2 ${
                isActive
                  ? "border-primary text-foreground bg-background"
                  : "border-transparent text-muted-foreground hover:text-foreground hover:bg-muted/40"
              }`}
            >
              {meta.tabLabel}
            </button>
          );
        })}
      </div>

      {/* Active tab content */}
      {fwKeys.map((key) => {
        if (key !== active) return null;
        const meta = FRAMEWORK_META[key];
        const data = report[key] ?? {};
        const score = data.score ?? 0;
        const controls = controlStatuses[key] ?? [];
        const passing = controls.filter((c) => c.status === "pass" || c.status === "attested").length;
        const failing = controls.filter((c) => c.status === "fail").length;

        return (
          <div key={key} className="p-5 flex flex-col sm:flex-row items-start sm:items-center gap-6">
            {/* Circular score */}
            <div className="flex flex-col items-center gap-1">
              <CircularScore score={score} size={72} />
              <span className="text-xs text-muted-foreground">Compliance</span>
            </div>

            {/* Stats */}
            <div className="flex-1 grid grid-cols-2 gap-3">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0" />
                <div>
                  <div className="text-lg font-bold text-green-500">{passing}</div>
                  <div className="text-xs text-muted-foreground">Passing controls</div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <XCircle className="w-4 h-4 text-red-500 flex-shrink-0" />
                <div>
                  <div className="text-lg font-bold text-red-500">{failing}</div>
                  <div className="text-xs text-muted-foreground">Failing controls</div>
                </div>
              </div>
            </div>

            {/* Export attestation */}
            <Button
              variant="outline"
              size="sm"
              className="flex-shrink-0"
              onClick={() => onExportAttestation(key)}
            >
              <Download className="w-3.5 h-3.5 mr-1.5" />
              Export Attestation
            </Button>
          </div>
        );
      })}
    </div>
  );
}

// ── Evidence Upload Dialog ────────────────────────────────────────────────

interface EvidenceUploadDialogProps {
  controlId: string;
  controlName: string;
  linkedFindings: any[];
  isLoadingFindings: boolean;
  onClose: () => void;
  onMarkCompliant: () => void;
}

function EvidenceUploadDialog({
  controlId,
  controlName,
  linkedFindings,
  isLoadingFindings,
  onClose,
  onMarkCompliant,
}: EvidenceUploadDialogProps) {
  const { toast } = useToast();
  const [evidenceText, setEvidenceText] = useState("");
  const [uploading, setUploading] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  async function handleUpload() {
    const file = fileRef.current?.files?.[0];
    let filename = "";
    let content_base64 = "";

    if (file) {
      filename = file.name;
      content_base64 = await new Promise<string>((resolve) => {
        const reader = new FileReader();
        reader.onload = () => resolve((reader.result as string).split(",")[1] ?? "");
        reader.readAsDataURL(file);
      });
    }

    if (!evidenceText && !filename) {
      toast({ title: "Provide text or upload a file", variant: "destructive" });
      return;
    }

    setUploading(true);
    try {
      const res = await fetch(`/api/compliance/evidence/${encodeURIComponent(controlId)}`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: evidenceText, filename, content_base64 }),
      });
      if (!res.ok) throw new Error();
      toast({ title: "Evidence uploaded successfully" });
      setEvidenceText("");
      if (fileRef.current) fileRef.current.value = "";
    } catch {
      toast({ title: "Failed to upload evidence", variant: "destructive" });
    } finally {
      setUploading(false);
    }
  }

  const SEV_COLORS: Record<string, string> = {
    critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22d3ee",
  };

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-2xl max-h-[85vh] flex flex-col">
        <DialogHeader>
          <DialogTitle className="text-base">{controlName}</DialogTitle>
          <p className="text-xs text-muted-foreground font-mono">{controlId}</p>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto space-y-5 py-2">
          {/* Linked findings */}
          <div>
            <h4 className="text-sm font-semibold mb-2">Linked Open Findings</h4>
            {isLoadingFindings ? (
              <div className="flex items-center gap-2 text-muted-foreground text-sm py-4">
                <RefreshCw className="w-4 h-4 animate-spin" /> Loading findings…
              </div>
            ) : linkedFindings.length === 0 ? (
              <div className="text-center py-6 text-muted-foreground text-sm border rounded-lg">
                <CheckCircle2 className="w-8 h-8 mx-auto mb-2 text-green-400 opacity-60" />
                No findings linked to this control
              </div>
            ) : (
              <div className="space-y-1.5">
                {linkedFindings.map((f: any) => {
                  const sev = f.severity ?? "info";
                  const color = SEV_COLORS[sev] ?? "#6b7280";
                  return (
                    <div
                      key={f.id ?? f._id}
                      className="flex items-center gap-3 p-2.5 rounded-lg border border-border"
                    >
                      <span
                        className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase flex-shrink-0"
                        style={{ background: `${color}22`, color }}
                      >
                        {sev}
                      </span>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{f.title}</p>
                        <p className="text-xs text-muted-foreground">{f.status ?? "open"}</p>
                      </div>
                      <Link href={`/findings/${f.id ?? f._id}`}>
                        <Button size="sm" variant="ghost" className="h-7 w-7 p-0">
                          <ExternalLink className="w-3.5 h-3.5" />
                        </Button>
                      </Link>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Evidence upload */}
          <div className="space-y-3 border rounded-lg p-4">
            <h4 className="text-sm font-semibold flex items-center gap-2">
              <Upload className="w-4 h-4" /> Upload Evidence
            </h4>
            <div>
              <Label className="text-xs mb-1 block">Evidence Notes</Label>
              <textarea
                value={evidenceText}
                onChange={(e) => setEvidenceText(e.target.value)}
                placeholder="Describe the evidence, remediation performed, or compensating controls..."
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm resize-none h-24"
              />
            </div>
            <div>
              <Label className="text-xs mb-1 block">Attach File (optional)</Label>
              <input
                ref={fileRef}
                type="file"
                className="text-sm text-muted-foreground file:mr-3 file:px-3 file:py-1 file:rounded file:border-0 file:bg-muted file:text-sm file:font-medium hover:file:bg-muted/80 cursor-pointer"
              />
            </div>
            <Button
              size="sm"
              disabled={uploading}
              onClick={handleUpload}
              className="w-full"
            >
              <Upload className="w-3.5 h-3.5 mr-1.5" />
              {uploading ? "Uploading…" : "Submit Evidence"}
            </Button>
          </div>

          {/* Manual override */}
          <div className="border border-blue-500/20 rounded-lg p-4 bg-blue-500/5">
            <h4 className="text-sm font-semibold flex items-center gap-2 mb-2">
              <CheckSquare className="w-4 h-4 text-blue-400" />
              Manual Compliance Override
            </h4>
            <p className="text-xs text-muted-foreground mb-3">
              If you have verified this control is compliant through a process outside the scanner, mark it as manually compliant.
            </p>
            <Button
              size="sm"
              variant="outline"
              className="border-blue-500/30 text-blue-400 hover:bg-blue-500/10"
              onClick={onMarkCompliant}
            >
              <CheckCircle2 className="w-3.5 h-3.5 mr-1.5" />
              Mark Compliant (Manual Override)
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
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

// ── Control drill-down panel (legacy, still used for expand-in-row) ────────

const SEV_COLORS: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22d3ee",
};

function ControlDrillDown({
  controlId,
  controlName,
  status,
  onClose,
}: {
  controlId: string;
  controlName: string;
  status: string;
  onClose: () => void;
}) {
  const { toast } = useToast();

  const { data: linkedFindings = [], isLoading } = useQuery<any[]>({
    queryKey: ["/api/compliance/controls", controlId, "findings"],
    queryFn: () =>
      fetch(`/api/compliance/controls/${controlId}/findings`, { credentials: "include" })
        .then(r => r.json())
        .then(d => Array.isArray(d) ? d : []),
    enabled: !!controlId,
  });

  const createRemediation = useMutation({
    mutationFn: (body: object) =>
      fetch("/api/remediations", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }).then(r => r.json()),
    onSuccess: () => toast({ title: "Remediation assigned" }),
    onError: () => toast({ title: "Failed to assign remediation", variant: "destructive" }),
  });

  function exportControlEvidence() {
    const header = "ID,Title,Severity,Status";
    const rows = linkedFindings.map((f: any) =>
      `${f.id ?? ""},${JSON.stringify(f.title ?? "")},${f.severity ?? ""},${f.status ?? ""}`
    );
    const csvContent = [header, ...rows].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `control-${controlId}-evidence.csv`; a.click();
    URL.revokeObjectURL(url);
  }

  const statusLabel: Record<string, { label: string; cls: string }> = {
    pass:     { label: "Pass",     cls: "text-green-400 border-green-400/30 bg-green-400/10" },
    fail:     { label: "Fail",     cls: "text-red-400 border-red-400/30 bg-red-400/10" },
    warning:  { label: "Warning",  cls: "text-yellow-400 border-yellow-400/30 bg-yellow-400/10" },
    attested: { label: "Attested", cls: "text-blue-400 border-blue-400/30 bg-blue-400/10" },
    untested: { label: "Untested", cls: "text-muted-foreground border-border bg-muted/20" },
  };
  const sl = statusLabel[status] ?? statusLabel.untested;

  return (
    <Dialog open onOpenChange={v => !v && onClose()}>
      <DialogContent className="sm:max-w-2xl max-h-[85vh] flex flex-col">
        <DialogHeader>
          <div className="flex items-start justify-between gap-3 pr-6">
            <div className="flex-1 min-w-0">
              <DialogTitle className="text-base leading-tight">{controlName}</DialogTitle>
              <p className="text-xs text-muted-foreground font-mono mt-1">{controlId}</p>
            </div>
            <Badge variant="outline" className={`text-xs flex-shrink-0 ${sl.cls}`}>
              {sl.label}
            </Badge>
          </div>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto space-y-4 py-2">
          {/* Linked Findings */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-sm font-semibold">Linked Findings</h4>
              <Button variant="outline" size="sm" onClick={exportControlEvidence} className="h-7 text-xs">
                <Download className="w-3 h-3 mr-1.5" /> Export Evidence
              </Button>
            </div>

            {isLoading ? (
              <div className="flex items-center gap-2 text-muted-foreground text-sm py-4">
                <RefreshCw className="w-4 h-4 animate-spin" /> Loading findings…
              </div>
            ) : linkedFindings.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground text-sm">
                <CheckCircle2 className="w-8 h-8 mx-auto mb-2 text-green-400 opacity-60" />
                No findings linked to this control
              </div>
            ) : (
              <div className="space-y-2">
                {linkedFindings.map((f: any) => {
                  const sev = f.severity ?? "info";
                  const color = SEV_COLORS[sev] ?? "#6b7280";
                  return (
                    <div
                      key={f.id ?? f._id}
                      className="flex items-center gap-3 p-3 rounded-lg border border-border hover:bg-accent/20 transition-colors"
                    >
                      <span
                        className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase flex-shrink-0"
                        style={{ background: `${color}22`, color }}
                      >
                        {sev}
                      </span>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{f.title}</p>
                        <p className="text-xs text-muted-foreground">{f.status ?? "open"}</p>
                      </div>
                      <div className="flex items-center gap-1.5 flex-shrink-0">
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-7 text-xs"
                          onClick={() =>
                            createRemediation.mutate({
                              finding_id: f.id ?? f._id,
                              title: `Remediate: ${f.title}`,
                              control_id: controlId,
                            })
                          }
                        >
                          Assign Remediation
                        </Button>
                        <Link href={`/findings/${f.id ?? f._id}`}>
                          <Button size="sm" variant="ghost" className="h-7 w-7 p-0">
                            <ExternalLink className="w-3.5 h-3.5" />
                          </Button>
                        </Link>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ComplianceDashboard() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [activeFramework, setActiveFramework] = useState("soc2");
  const [expandedControl, setExpandedControl] = useState<string | null>(null);
  const [attestTarget, setAttestTarget] = useState<{ framework: string; control: { id: string; name: string } } | null>(null);
  const [drillDownControl, setDrillDownControl] = useState<{ id: string; name: string; status: string } | null>(null);
  const [evidenceDialogControl, setEvidenceDialogControl] = useState<{ id: string; name: string } | null>(null);

  const { data: report, isLoading, refetch } = useQuery<any>({
    queryKey: ["/api/compliance/report"],
    queryFn: () => fetch("/api/compliance/report", { credentials: "include" }).then(r => r.json()),
  });

  const { data: frameworkReportData } = useQuery<any>({
    queryKey: ["/api/compliance/report", activeFramework],
    queryFn: () =>
      fetch(`/api/compliance/report/${activeFramework}`, { credentials: "include" }).then(r => r.json()),
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

  // Findings for evidence dialog
  const { data: evidenceFindings = [], isLoading: isLoadingEvidence } = useQuery<any[]>({
    queryKey: ["/api/compliance/controls", evidenceDialogControl?.id, "findings"],
    queryFn: () =>
      fetch(`/api/compliance/controls/${evidenceDialogControl!.id}/findings`, { credentials: "include" })
        .then(r => r.json())
        .then(d => Array.isArray(d) ? d : []),
    enabled: !!evidenceDialogControl,
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

  function exportAttestation(fw: string) {
    fetch(`/api/compliance/attestation/${fw}`, { credentials: "include" })
      .then((r) => r.ok ? r.json() : Promise.reject())
      .then((data) => {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `attestation-${fw}-${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
        URL.revokeObjectURL(url);
        toast({ title: "Attestation exported" });
      })
      .catch(() => toast({ title: "Export failed — generating from local data", variant: "destructive" }));
  }

  function handleMarkCompliant(controlId: string, controlName: string) {
    if (!attestTarget) {
      setAttestTarget({ framework: activeFramework, control: { id: controlId, name: controlName } });
      setEvidenceDialogControl(null);
    }
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

  // Build control statuses for each framework (for the tab summary)
  const allControlStatuses: Record<string, Array<{ status: string }>> = {};
  for (const fw of ["pci_dss", "soc2", "hipaa", "iso27001"]) {
    const fwControls = FRAMEWORK_CONTROLS[fw] ?? [];
    const fwAttestations = attestations.filter((a: any) => a.framework === fw);
    const fwAttestedIds = new Set(fwAttestations.map((a: any) => a.control_id));
    allControlStatuses[fw] = fwControls.map((ctrl) => {
      const matchingFindings = allFindings.filter(f => ctrl.categories.includes(f.category ?? ""));
      const attested = fwAttestedIds.has(ctrl.id);
      const hasCritHigh = matchingFindings.some(f => f.severity === "critical" || f.severity === "high");
      let status: string;
      if (ctrl.categories.length === 0) status = "untested";
      else if (attested && matchingFindings.length === 0) status = "attested";
      else if (matchingFindings.length === 0) status = "pass";
      else if (hasCritHigh) status = "fail";
      else status = "warning";
      return { status };
    });
  }

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

      {/* ── Framework Selector Tabs (SOC2 | ISO 27001 | PCI-DSS | HIPAA) ── */}
      <FrameworkTabs
        active={activeFramework}
        onChange={setActiveFramework}
        report={report}
        controlStatuses={allControlStatuses}
        onExportAttestation={exportAttestation}
      />

      {/* ── Per-framework score summary ── */}
      <div className="grid grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-4 text-center">
            <div className="text-3xl font-bold text-green-400">{frameworkReportData?.score ?? report?.[activeFramework]?.score ?? 0}%</div>
            <div className="text-xs text-muted-foreground mt-1">Compliance Score</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <div className="text-3xl font-bold text-green-400">
              {frameworkReportData?.passing ?? allControlStatuses[activeFramework]?.filter(c => c.status === "pass" || c.status === "attested").length ?? 0}
            </div>
            <div className="text-xs text-muted-foreground mt-1">Passing Controls</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 text-center">
            <div className="text-3xl font-bold text-red-400">
              {frameworkReportData?.failing ?? allControlStatuses[activeFramework]?.filter(c => c.status === "fail").length ?? 0}
            </div>
            <div className="text-xs text-muted-foreground mt-1">Failing Controls</div>
          </CardContent>
        </Card>
      </div>

      {/* Framework score cards (secondary overview) */}
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
                    onClick={() => {
                      setExpandedControl(isOpen ? null : ctrl.id);
                      if (!isOpen) {
                        // Open evidence dialog for failing controls
                        if (ctrl.status === "fail" || ctrl.status === "warning") {
                          setEvidenceDialogControl({ id: ctrl.id, name: ctrl.name });
                        } else {
                          setDrillDownControl({ id: ctrl.id, name: ctrl.name, status: ctrl.status });
                        }
                      }
                    }}
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
                      {(ctrl.status === "fail" || ctrl.status === "warning") && (
                        <Button
                          size="sm" variant="ghost" className="h-6 text-[10px] px-2 text-blue-400"
                          onClick={e => { e.stopPropagation(); setEvidenceDialogControl({ id: ctrl.id, name: ctrl.name }); }}
                        >
                          <Upload className="w-3 h-3 mr-1" />Evidence
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

      {/* Control drill-down panel (for pass/attested/untested) */}
      {drillDownControl && (
        <ControlDrillDown
          controlId={drillDownControl.id}
          controlName={drillDownControl.name}
          status={drillDownControl.status}
          onClose={() => setDrillDownControl(null)}
        />
      )}

      {/* Evidence Upload Dialog (for fail/warning controls) */}
      {evidenceDialogControl && (
        <EvidenceUploadDialog
          controlId={evidenceDialogControl.id}
          controlName={evidenceDialogControl.name}
          linkedFindings={evidenceFindings}
          isLoadingFindings={isLoadingEvidence}
          onClose={() => setEvidenceDialogControl(null)}
          onMarkCompliant={() => {
            handleMarkCompliant(evidenceDialogControl.id, evidenceDialogControl.name);
          }}
        />
      )}

      <p className="text-xs text-center text-muted-foreground">
        Compliance scores are estimates based on discovered vulnerabilities and should supplement, not replace, official audits.
      </p>
    </div>
  );
}
