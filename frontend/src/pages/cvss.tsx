import { useState, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis, ResponsiveContainer,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Save, Import, Copy, Check, Plus, Trash2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useMutation, useQueryClient } from "@tanstack/react-query";

// ─── CVSS 3.1 Data ───────────────────────────────────────────────────────────

const BASE_METRICS = [
  { id: "AV", label: "Attack Vector",         group: "Exploitability", options: [{ v: "N", l: "Network", s: 0.85 }, { v: "A", l: "Adjacent", s: 0.62 }, { v: "L", l: "Local", s: 0.55 }, { v: "P", l: "Physical", s: 0.2 }] },
  { id: "AC", label: "Attack Complexity",      group: "Exploitability", options: [{ v: "L", l: "Low", s: 0.77 }, { v: "H", l: "High", s: 0.44 }] },
  { id: "PR", label: "Privileges Required",    group: "Exploitability", options: [{ v: "N", l: "None", s: 0.85 }, { v: "L", l: "Low", s: 0.62 }, { v: "H", l: "High", s: 0.27 }] },
  { id: "UI", label: "User Interaction",       group: "Exploitability", options: [{ v: "N", l: "None", s: 0.85 }, { v: "R", l: "Required", s: 0.62 }] },
  { id: "S",  label: "Scope",                  group: "Scope",          options: [{ v: "U", l: "Unchanged", s: 0 }, { v: "C", l: "Changed", s: 1 }] },
  { id: "C",  label: "Confidentiality Impact", group: "Impact",         options: [{ v: "N", l: "None", s: 0 }, { v: "L", l: "Low", s: 0.22 }, { v: "H", l: "High", s: 0.56 }] },
  { id: "I",  label: "Integrity Impact",       group: "Impact",         options: [{ v: "N", l: "None", s: 0 }, { v: "L", l: "Low", s: 0.22 }, { v: "H", l: "High", s: 0.56 }] },
  { id: "A",  label: "Availability Impact",    group: "Impact",         options: [{ v: "N", l: "None", s: 0 }, { v: "L", l: "Low", s: 0.22 }, { v: "H", l: "High", s: 0.56 }] },
];

const TEMPORAL_METRICS = [
  { id: "E",  label: "Exploit Code Maturity",  options: [{ v: "X", l: "Not Defined", s: 1 }, { v: "U", l: "Unproven", s: 0.91 }, { v: "P", l: "Proof-of-Concept", s: 0.94 }, { v: "F", l: "Functional", s: 0.97 }, { v: "H", l: "High", s: 1 }] },
  { id: "RL", label: "Remediation Level",       options: [{ v: "X", l: "Not Defined", s: 1 }, { v: "O", l: "Official Fix", s: 0.95 }, { v: "T", l: "Temporary Fix", s: 0.96 }, { v: "W", l: "Workaround", s: 0.97 }, { v: "U", l: "Unavailable", s: 1 }] },
  { id: "RC", label: "Report Confidence",       options: [{ v: "X", l: "Not Defined", s: 1 }, { v: "U", l: "Unknown", s: 0.92 }, { v: "R", l: "Reasonable", s: 0.96 }, { v: "C", l: "Confirmed", s: 1 }] },
];

const ENV_METRICS = [
  { id: "CR",  label: "Confidentiality Req.", options: [{ v: "X", l: "Not Defined", s: 1 }, { v: "L", l: "Low", s: 0.5 }, { v: "M", l: "Medium", s: 1 }, { v: "H", l: "High", s: 1.5 }] },
  { id: "IR",  label: "Integrity Req.",        options: [{ v: "X", l: "Not Defined", s: 1 }, { v: "L", l: "Low", s: 0.5 }, { v: "M", l: "Medium", s: 1 }, { v: "H", l: "High", s: 1.5 }] },
  { id: "AR",  label: "Availability Req.",     options: [{ v: "X", l: "Not Defined", s: 1 }, { v: "L", l: "Low", s: 0.5 }, { v: "M", l: "Medium", s: 1 }, { v: "H", l: "High", s: 1.5 }] },
  { id: "MAV", label: "Modified Attack Vector",options: [{ v: "X", l: "Not Defined", s: 0.85 }, { v: "N", l: "Network", s: 0.85 }, { v: "A", l: "Adjacent", s: 0.62 }, { v: "L", l: "Local", s: 0.55 }, { v: "P", l: "Physical", s: 0.2 }] },
  { id: "MAC", label: "Modified Attack Complexity", options: [{ v: "X", l: "Not Defined", s: 0.77 }, { v: "L", l: "Low", s: 0.77 }, { v: "H", l: "High", s: 0.44 }] },
  { id: "MUI", label: "Modified User Interaction",  options: [{ v: "X", l: "Not Defined", s: 0.85 }, { v: "N", l: "None", s: 0.85 }, { v: "R", l: "Required", s: 0.62 }] },
];

// ─── CVSS 4.0 simplified data ─────────────────────────────────────────────────

const CVSS4_METRICS = [
  { id: "AV",  label: "Attack Vector",        options: [{ v: "N", l: "Network", s: 0.85 }, { v: "A", l: "Adjacent", s: 0.62 }, { v: "L", l: "Local", s: 0.55 }, { v: "P", l: "Physical", s: 0.2 }] },
  { id: "AC",  label: "Attack Complexity",     options: [{ v: "L", l: "Low", s: 0.77 }, { v: "H", l: "High", s: 0.44 }] },
  { id: "AT",  label: "Attack Requirements",   options: [{ v: "N", l: "None", s: 0.85 }, { v: "P", l: "Present", s: 0.62 }] },
  { id: "PR",  label: "Privileges Required",   options: [{ v: "N", l: "None", s: 0.85 }, { v: "L", l: "Low", s: 0.62 }, { v: "H", l: "High", s: 0.27 }] },
  { id: "UI",  label: "User Interaction",      options: [{ v: "N", l: "None", s: 0.85 }, { v: "P", l: "Passive", s: 0.62 }, { v: "A", l: "Active", s: 0.45 }] },
  { id: "VC",  label: "Vulnerable System Confidentiality", options: [{ v: "N", l: "None", s: 0 }, { v: "L", l: "Low", s: 0.22 }, { v: "H", l: "High", s: 0.56 }] },
  { id: "VI",  label: "Vulnerable System Integrity",       options: [{ v: "N", l: "None", s: 0 }, { v: "L", l: "Low", s: 0.22 }, { v: "H", l: "High", s: 0.56 }] },
  { id: "VA",  label: "Vulnerable System Availability",    options: [{ v: "N", l: "None", s: 0 }, { v: "L", l: "Low", s: 0.22 }, { v: "H", l: "High", s: 0.56 }] },
];

// ─── Defaults ─────────────────────────────────────────────────────────────────

const BASE_DEFAULTS: Record<string, string> = { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "N", I: "N", A: "N" };
const TEMP_DEFAULTS: Record<string, string> = { E: "X", RL: "X", RC: "X" };
const ENV_DEFAULTS: Record<string, string>  = { CR: "X", IR: "X", AR: "X", MAV: "X", MAC: "X", MUI: "X" };
const CVSS4_DEFAULTS: Record<string, string> = { AV: "N", AC: "L", AT: "N", PR: "N", UI: "N", VC: "N", VI: "N", VA: "N" };

// ─── Scoring ──────────────────────────────────────────────────────────────────

function calcBase(vals: Record<string, string>): number {
  const getS = (id: string) => {
    const m = BASE_METRICS.find(m => m.id === id);
    const opt = m?.options.find(o => o.v === vals[id]);
    return opt?.s ?? 0;
  };
  const iss = 1 - (1 - getS("C")) * (1 - getS("I")) * (1 - getS("A"));
  const scopeChanged = vals["S"] === "C";
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploitability = 8.22 * getS("AV") * getS("AC") * getS("PR") * getS("UI");
  if (impact <= 0) return 0;
  const raw = scopeChanged ? Math.min(1.08 * (impact + exploitability), 10) : Math.min(impact + exploitability, 10);
  return Math.round(raw * 10) / 10;
}

function calcTemporal(base: number, tVals: Record<string, string>): number {
  const getT = (id: string) => {
    const m = TEMPORAL_METRICS.find(m => m.id === id);
    return m?.options.find(o => o.v === tVals[id])?.s ?? 1;
  };
  return Math.round(base * getT("E") * getT("RL") * getT("RC") * 10) / 10;
}

function calcCvss4(vals: Record<string, string>): number {
  const getS = (id: string) => {
    const m = CVSS4_METRICS.find(m => m.id === id);
    return m?.options.find(o => o.v === vals[id])?.s ?? 0;
  };
  const iss = 1 - (1 - getS("VC")) * (1 - getS("VI")) * (1 - getS("VA"));
  const impact = 6.42 * iss;
  const exploit = 8.22 * getS("AV") * getS("AC") * getS("PR") * getS("UI");
  if (impact <= 0) return 0;
  return Math.round(Math.min(impact + exploit, 10) * 10) / 10;
}

function severityLabel(s: number) {
  if (s === 0) return "None";
  if (s < 4) return "Low";
  if (s < 7) return "Medium";
  if (s < 9) return "High";
  return "Critical";
}

function severityColor(s: number) {
  if (s === 0) return "#6b7280";
  if (s < 4) return "#22d3ee";
  if (s < 7) return "#eab308";
  if (s < 9) return "#f97316";
  return "#ef4444";
}

// ─── Vector string parse ──────────────────────────────────────────────────────

function parseVector(vec: string): Record<string, string> | null {
  const parts = vec.replace(/^CVSS:3\.[01]\//, "").split("/");
  const result: Record<string, string> = {};
  for (const p of parts) {
    const [k, v] = p.split(":");
    if (k && v) result[k] = v;
  }
  return Object.keys(result).length > 0 ? result : null;
}

function buildVector(vals: Record<string, string>, tVals: Record<string, string>): string {
  const base = BASE_METRICS.map(m => `${m.id}:${vals[m.id] ?? "?"}`).join("/");
  const temp = TEMPORAL_METRICS.map(m => `${m.id}:${tVals[m.id] ?? "X"}`).join("/");
  return `CVSS:3.1/${base}/${temp}`;
}

// ─── Score display ────────────────────────────────────────────────────────────

function ScoreDisplay({ score, label, size = "lg" }: { score: number; label: string; size?: "sm" | "lg" }) {
  const color = severityColor(score);
  const sev = severityLabel(score);
  const pct = (score / 10) * 100;

  return (
    <div className="text-center">
      <div className={`font-bold font-mono ${size === "lg" ? "text-5xl" : "text-3xl"}`} style={{ color }}>{score.toFixed(1)}</div>
      <div className={`font-semibold uppercase mt-1 ${size === "lg" ? "text-lg" : "text-sm"}`} style={{ color }}>{sev}</div>
      <p className="text-xs text-muted-foreground mt-0.5">{label}</p>
      {/* Gradient bar */}
      <div className="mt-3 h-2.5 rounded-full overflow-hidden" style={{ background: "hsl(var(--muted))" }}>
        <div className="h-full rounded-full transition-all duration-500"
          style={{
            width: `${pct}%`,
            background: `linear-gradient(to right, #22d3ee, #eab308, #f97316, #ef4444)`,
          }} />
      </div>
      <div className="flex justify-between text-[9px] text-muted-foreground mt-0.5 font-mono">
        <span>0</span><span>None · Low · Med · High · Crit</span><span>10</span>
      </div>
    </div>
  );
}

// ─── Metric selector ──────────────────────────────────────────────────────────

function MetricRow({ metric, value, onChange }: {
  metric: { id: string; label: string; options: { v: string; l: string; s: number }[] };
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="flex items-center gap-3">
      <span className="text-xs font-medium text-muted-foreground w-36 flex-shrink-0">{metric.label}</span>
      <div className="flex gap-1.5 flex-wrap">
        {metric.options.map(o => (
          <button key={o.v} onClick={() => onChange(o.v)}
            className="text-xs px-2.5 py-1 rounded border transition-all font-medium"
            style={value === o.v
              ? { background: "hsl(var(--primary))", color: "white", borderColor: "hsl(var(--primary))" }
              : { background: "transparent", borderColor: "hsl(var(--border))", color: "hsl(var(--muted-foreground))" }}>
            {o.l}
          </button>
        ))}
      </div>
    </div>
  );
}

// ─── Radar chart ─────────────────────────────────────────────────────────────

function RadarBreakdown({ vals, color }: { vals: Record<string, string>; color: string }) {
  const getS = (id: string) => {
    const m = BASE_METRICS.find(m => m.id === id);
    const opt = m?.options.find(o => o.v === vals[id]);
    return Math.round((opt?.s ?? 0) * 100);
  };

  const data = [
    { subject: "Attack Vector", A: getS("AV") },
    { subject: "Attack Complexity", A: getS("AC") },
    { subject: "Privileges", A: getS("PR") },
    { subject: "User Interaction", A: getS("UI") },
    { subject: "Confidentiality", A: getS("C") },
    { subject: "Integrity", A: getS("I") },
    { subject: "Availability", A: getS("A") },
  ];

  return (
    <ResponsiveContainer width="100%" height={220}>
      <RadarChart data={data}>
        <PolarGrid stroke="hsl(var(--border))" />
        <PolarAngleAxis dataKey="subject" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
        <Radar dataKey="A" stroke={color} fill={color} fillOpacity={0.25} />
      </RadarChart>
    </ResponsiveContainer>
  );
}

// ─── Save-to-finding dialog ───────────────────────────────────────────────────

function SaveDialog({ score, onClose }: { score: number; onClose: () => void }) {
  const [selectedId, setSelectedId] = useState("");
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data } = useQuery<{ items: Array<{ id: string; title: string; cvss_score?: number }> }>({
    queryKey: ["/api/findings", "save-cvss"],
    queryFn: () =>
      fetch("/api/findings?page_size=50", { credentials: "include" }).then(r => r.json()),
  });

  const save = useMutation({
    mutationFn: () =>
      fetch(`/api/findings/${selectedId}`, {
        method: "PATCH", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cvss_score: score }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/findings"] });
      toast({ title: "CVSS score saved", description: `Score ${score} applied to finding.` });
      onClose();
    },
  });

  return (
    <DialogContent className="sm:max-w-sm">
      <DialogHeader><DialogTitle>Save CVSS Score to Finding</DialogTitle></DialogHeader>
      <div className="space-y-3 py-2">
        <div className="rounded-md p-3 text-center" style={{ background: "hsl(var(--muted))" }}>
          <span className="text-2xl font-bold font-mono" style={{ color: severityColor(score) }}>{score.toFixed(1)}</span>
          <span className="text-sm text-muted-foreground ml-2">{severityLabel(score)}</span>
        </div>
        <select
          className="w-full text-sm bg-card border border-border rounded-md px-3 py-2 outline-none"
          value={selectedId}
          onChange={e => setSelectedId(e.target.value)}
        >
          <option value="">Select a finding…</option>
          {(data?.items ?? []).map(f => (
            <option key={f.id} value={f.id}>{f.title} {f.cvss_score != null ? `(current: ${f.cvss_score})` : ""}</option>
          ))}
        </select>
        <Button className="w-full" disabled={!selectedId || save.isPending} onClick={() => save.mutate()}>
          {save.isPending ? "Saving…" : "Save Score"}
        </Button>
      </div>
    </DialogContent>
  );
}

// ─── History entry ────────────────────────────────────────────────────────────

interface HistoryEntry {
  id: number;
  label: string;
  base: number;
  vector: string;
  vals: Record<string, string>;
  tVals: Record<string, string>;
}

// ─── Calculator panel ─────────────────────────────────────────────────────────

function CalculatorPanel({ label, showCompare = false }: { label: string; showCompare?: boolean }) {
  const [vals, setVals] = useState({ ...BASE_DEFAULTS });
  const [tVals, setTVals] = useState({ ...TEMP_DEFAULTS });
  const [eVals, setEVals] = useState({ ...ENV_DEFAULTS });
  const [vectorInput, setVectorInput] = useState("");
  const [vectorError, setVectorError] = useState("");
  const [saveOpen, setSaveOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const [cvssVersion, setCvssVersion] = useState<"3.1" | "4.0">("3.1");
  const [cvss4Vals, setCvss4Vals] = useState({ ...CVSS4_DEFAULTS });
  const { toast } = useToast();

  const base = cvssVersion === "4.0" ? calcCvss4(cvss4Vals) : calcBase(vals);
  const temporal = cvssVersion === "4.0" ? base : calcTemporal(base, tVals);
  const color = severityColor(base);

  const vector = buildVector(vals, tVals);

  function importVector() {
    const parsed = parseVector(vectorInput);
    if (!parsed) { setVectorError("Invalid vector string"); return; }
    setVectorError("");
    const newBase: Record<string, string> = { ...BASE_DEFAULTS };
    const newTemp: Record<string, string> = { ...TEMP_DEFAULTS };
    for (const [k, v] of Object.entries(parsed)) {
      if (k in BASE_DEFAULTS) newBase[k] = v;
      if (k in TEMP_DEFAULTS) newTemp[k] = v;
    }
    setVals(newBase);
    setTVals(newTemp);
    setVectorInput("");
    toast({ title: "Vector imported" });
  }

  async function copyVector() {
    await navigator.clipboard.writeText(vector);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const metricsToShow = cvssVersion === "4.0" ? CVSS4_METRICS : BASE_METRICS;
  const currentVals = cvssVersion === "4.0" ? cvss4Vals : vals;
  const setCurrentVals = cvssVersion === "4.0"
    ? (id: string, v: string) => setCvss4Vals(p => ({ ...p, [id]: v }))
    : (id: string, v: string) => setVals(p => ({ ...p, [id]: v }));

  return (
    <div className="space-y-5">
      {/* Version + vector controls */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-1 p-1 rounded-md" style={{ background: "hsl(var(--muted))" }}>
          {(["3.1", "4.0"] as const).map(v => (
            <button key={v} onClick={() => setCvssVersion(v)}
              className="text-xs font-bold px-3 py-1 rounded transition-all"
              style={cvssVersion === v
                ? { background: "hsl(var(--primary))", color: "white" }
                : { color: "hsl(var(--muted-foreground))" }}>
              CVSS v{v}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2 flex-1 min-w-0">
          <input
            className="flex-1 text-xs font-mono bg-card border border-border rounded px-2 py-1.5 outline-none placeholder:text-muted-foreground"
            placeholder="Paste vector: AV:N/AC:L/PR:N/…"
            value={vectorInput}
            onChange={e => { setVectorInput(e.target.value); setVectorError(""); }}
            onKeyDown={e => e.key === "Enter" && importVector()}
          />
          <Button variant="outline" size="sm" onClick={importVector}>
            <Import className="w-3.5 h-3.5 mr-1" />Import
          </Button>
        </div>
        {vectorError && <span className="text-xs text-red-400">{vectorError}</span>}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        {/* Left: metrics */}
        <div className="xl:col-span-2 space-y-5">
          {/* Base metrics */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Base Score Metrics</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {metricsToShow.map(m => (
                <MetricRow
                  key={m.id} metric={m}
                  value={currentVals[m.id] ?? ""}
                  onChange={v => setCurrentVals(m.id, v)}
                />
              ))}
            </CardContent>
          </Card>

          {/* Temporal */}
          {cvssVersion === "3.1" && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm">Temporal Metrics</CardTitle>
                <CardDescription className="text-xs">Reflects current exploit state and fix availability</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {TEMPORAL_METRICS.map(m => (
                  <MetricRow key={m.id} metric={m} value={tVals[m.id] ?? "X"} onChange={v => setTVals(p => ({ ...p, [m.id]: v }))} />
                ))}
              </CardContent>
            </Card>
          )}

          {/* Environmental */}
          {cvssVersion === "3.1" && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm">Environmental Metrics</CardTitle>
                <CardDescription className="text-xs">Adjust for your specific environment and asset importance</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {ENV_METRICS.map(m => (
                  <MetricRow key={m.id} metric={m} value={eVals[m.id] ?? "X"} onChange={v => setEVals(p => ({ ...p, [m.id]: v }))} />
                ))}
              </CardContent>
            </Card>
          )}
        </div>

        {/* Right: scores + radar */}
        <div className="space-y-4">
          <Card>
            <CardContent className="pt-5 pb-4 space-y-5">
              <ScoreDisplay score={base} label="Base Score" size="lg" />
              {cvssVersion === "3.1" && temporal !== base && (
                <ScoreDisplay score={temporal} label="Temporal Score" size="sm" />
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Metric Breakdown</CardTitle>
            </CardHeader>
            <CardContent className="pt-0">
              <RadarBreakdown vals={cvssVersion === "4.0" ? { AV: cvss4Vals.AV, AC: cvss4Vals.AC, PR: cvss4Vals.PR, UI: cvss4Vals.UI, S: "U", C: cvss4Vals.VC, I: cvss4Vals.VI, A: cvss4Vals.VA } : vals} color={color} />
            </CardContent>
          </Card>

          {/* Vector string */}
          <Card>
            <CardContent className="pt-4 pb-3">
              <p className="text-[10px] text-muted-foreground mb-1.5">Vector String</p>
              <div className="flex items-center gap-2">
                <code className="text-[10px] font-mono bg-muted/50 rounded px-2 py-1.5 flex-1 overflow-x-auto break-all">{vector}</code>
                <button onClick={copyVector} className="text-muted-foreground hover:text-foreground flex-shrink-0">
                  {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            </CardContent>
          </Card>

          <div className="flex gap-2">
            <Button className="flex-1" size="sm" variant="outline" onClick={() => setSaveOpen(true)}>
              <Save className="w-3.5 h-3.5 mr-1.5" />Save to Finding
            </Button>
          </div>
        </div>
      </div>

      <Dialog open={saveOpen} onOpenChange={o => !o && setSaveOpen(false)}>
        {saveOpen && <SaveDialog score={base} onClose={() => setSaveOpen(false)} />}
      </Dialog>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function CVSSCalculator() {
  const [mode, setMode] = useState<"single" | "compare">("single");
  const [history, setHistory] = useState<HistoryEntry[]>([]);

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">CVSS Calculator</h1>
          <p className="text-muted-foreground">CVSS v3.1 & v4.0 with Temporal, Environmental metrics and radar visualization.</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setMode("single")}
            className="text-xs font-medium px-3 py-1.5 rounded border transition-all"
            style={mode === "single" ? { background: "hsl(var(--primary))", color: "white", borderColor: "hsl(var(--primary))" } : { borderColor: "hsl(var(--border))", color: "hsl(var(--muted-foreground))" }}>
            Single
          </button>
          <button onClick={() => setMode("compare")}
            className="text-xs font-medium px-3 py-1.5 rounded border transition-all"
            style={mode === "compare" ? { background: "hsl(var(--primary))", color: "white", borderColor: "hsl(var(--primary))" } : { borderColor: "hsl(var(--border))", color: "hsl(var(--muted-foreground))" }}>
            Side-by-Side Compare
          </button>
        </div>
      </div>

      {mode === "single" ? (
        <CalculatorPanel label="Calculator" />
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          <div>
            <h2 className="text-sm font-semibold mb-3 px-1 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-blue-500" />Before Mitigation
            </h2>
            <CalculatorPanel label="Before" showCompare />
          </div>
          <div>
            <h2 className="text-sm font-semibold mb-3 px-1 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-green-500" />After Mitigation
            </h2>
            <CalculatorPanel label="After" showCompare />
          </div>
        </div>
      )}
    </div>
  );
}
