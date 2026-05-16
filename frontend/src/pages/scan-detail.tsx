import { useState, useEffect, useRef } from "react";
import { useParams, useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import {
  useGetScanJob,
  useGetScanJobFindings,
  useGetScanJobAttackSurface
} from "@/api-client";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Download, AlertTriangle, Clock, Activity, FileText, CheckCircle2, XCircle,
  Radio, Loader2, GitCompare, Link2, StopCircle, Pause, Play, Moon, Sun,
  Copy, RefreshCw, X, Send, GitBranch, Filter, Sparkles, ChevronRight, MinusCircle,
} from "lucide-react";
import { format } from "date-fns";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import { useToast } from "@/hooks/use-toast";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { MarkdownContent } from "@/lib/markdown";

// Reusable SSE streaming panel for scan-level AI features.
function ScanAiPanel({
  fetchFn,
  title,
  description,
  buttonLabel,
  icon,
  emptyText,
  disabled = false,
  disabledReason = "",
}: {
  fetchFn: () => Promise<Response>;
  title: string;
  description: string;
  buttonLabel: string;
  icon: React.ReactNode;
  emptyText: string;
  disabled?: boolean;
  disabledReason?: string;
}) {
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [followUp, setFollowUp] = useState("");
  const [followUpLoading, setFollowUpLoading] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const { toast } = useToast();

  async function generate() {
    setText(""); setDone(false); setLoading(true);
    abortRef.current = new AbortController();
    try {
      const res = await fetchFn();
      if (!res.ok) throw new Error("Request failed");
      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { done: dr, value } = await reader.read();
        if (dr) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try {
            const d = JSON.parse(line.slice(6));
            if (d.content) setText(p => p + d.content);
            if (d.done) setDone(true);
            if (d.error) {
              setText(p => p || "AI generation failed.");
              toast({ title: "AI Error", description: d.error, variant: "destructive" });
            }
          } catch { /* */ }
        }
      }
      setDone(true);
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        setDone(true);
      } else {
        const msg = "Failed to connect to AI service. Please try again.";
        setText(msg);
        toast({ title: "AI Error", description: msg, variant: "destructive" });
      }
    } finally { setLoading(false); abortRef.current = null; }
  }

  async function sendFollowUp() {
    if (!followUp.trim() || followUpLoading) return;
    const question = followUp;
    setFollowUp("");
    setFollowUpLoading(true);
    abortRef.current = new AbortController();
    setText(p => p + `\n\n---\n\n**You:** ${question}\n\n**Marcus:**\n`);
    try {
      const r = await fetch("/api/ai/chat", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: question }),
        signal: abortRef.current.signal,
      });
      if (!r.ok) throw new Error("Failed");
      const reader = r.body!.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { done: dr, value } = await reader.read();
        if (dr) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try {
            const d = JSON.parse(line.slice(6));
            if (d.content) setText(p => p + d.content);
          } catch { /* */ }
        }
      }
    } catch (err) {
      if (!(err instanceof Error && err.name === "AbortError")) {
        setText(p => p + "\n\n*Failed to get response.*");
      }
    } finally { setFollowUpLoading(false); abortRef.current = null; }
  }

  const isStreaming = loading || followUpLoading;

  async function copyAll() {
    await navigator.clipboard.writeText(text);
    toast({ title: "Copied to clipboard" });
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle>{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </div>
        <div className="flex gap-2 shrink-0 flex-wrap justify-end">
          {text && !isStreaming && (
            <>
              <Button size="sm" variant="outline" onClick={copyAll} className="gap-1.5 h-8">
                <Copy className="w-3.5 h-3.5" />Copy
              </Button>
              <Button size="sm" variant="outline" onClick={generate} disabled={disabled} className="gap-1.5 h-8">
                <RefreshCw className="w-3.5 h-3.5" />Regenerate
              </Button>
            </>
          )}
          {isStreaming && (
            <Button size="sm" variant="outline" onClick={() => abortRef.current?.abort()}
              className="gap-1.5 h-8 border-red-500/40 text-red-400 hover:bg-red-500/10">
              <X className="w-3.5 h-3.5" />Stop
            </Button>
          )}
          <Button onClick={generate} disabled={isStreaming || disabled} size="sm"
            className="bg-violet-600 hover:bg-violet-700 text-white gap-2 h-8"
            title={disabled ? disabledReason : ""}>
            {loading ? <><Loader2 className="w-4 h-4 animate-spin" />Generating…</> : <>{icon}{buttonLabel}</>}
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {!text && !isStreaming && (
          <div className="text-center py-12 text-muted-foreground text-sm">
            {disabled ? disabledReason : emptyText}
          </div>
        )}
        {(text || isStreaming) && (
          <div className="prose prose-sm dark:prose-invert max-w-none leading-relaxed">
            <MarkdownContent content={text} />
            {isStreaming && <span className="inline-block w-2 h-4 bg-violet-400 animate-pulse ml-1 align-middle" />}
          </div>
        )}
        {done && (
          <div className="mt-4 pt-3 border-t border-border space-y-2">
            <p className="text-xs text-muted-foreground">AI Security Engine · Ask a follow-up below</p>
            <div className="flex gap-2">
              <Input
                placeholder="Ask a follow-up question..."
                value={followUp}
                onChange={e => setFollowUp(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendFollowUp(); } }}
                disabled={followUpLoading}
                className="flex-1 h-8 text-sm"
              />
              <Button size="sm" onClick={sendFollowUp} disabled={followUpLoading || !followUp.trim()} className="h-8">
                {followUpLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-[hsl(var(--critical))] text-white",
    high: "bg-[hsl(var(--high))] text-white",
    medium: "bg-[hsl(var(--medium))] text-black",
    low: "bg-[hsl(var(--low))] text-black",
    info: "bg-[hsl(var(--info))] text-white",
  };
  return (
    <Badge className={`${colors[severity.toLowerCase()]} border-none uppercase text-[10px]`}>
      {severity}
    </Badge>
  );
}

export default function ScanDetail() {
  const params = useParams();
  const [, setLocation] = useLocation();
  const scanId = params.id as string;
  const { toast } = useToast();
  const qc = useQueryClient();

  const [terminalDark, setTerminalDark] = useState(true);
  const [compareTargetId, setCompareTargetId] = useState("");
  const [dedupeResult, setDedupeResult] = useState<{ duplicates: Array<{ group: number[]; reason: string; findings: Array<{ id: string; title: string; endpoint: string; severity: string }> }> } | null>(null);
  const [dedupeLoading, setDedupeLoading] = useState(false);

  const cancelScan = useMutation({
    mutationFn: () =>
      fetch(`/api/scan-jobs/${scanId}/cancel`, { method: "POST", credentials: "include" }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/scan-jobs", scanId] });
      toast({ title: "Scan cancelled" });
    },
  });

  const pauseScan = useMutation({
    mutationFn: () =>
      fetch(`/api/scan-jobs/${scanId}/pause`, { method: "POST", credentials: "include" }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/scan-jobs", scanId] });
      toast({ title: "Scan paused" });
    },
  });

  const resumeScan = useMutation({
    mutationFn: () =>
      fetch(`/api/scan-jobs/${scanId}/resume`, { method: "POST", credentials: "include" }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/scan-jobs", scanId] });
      toast({ title: "Scan resumed" });
    },
  });

  const [diffLoaded, setDiffLoaded] = useState(false);
  const [diffResult, setDiffResult] = useState<any>(null);
  const [diffLoading, setDiffLoading] = useState(false);
  const [compareFetching, setCompareFetching] = useState(false);

  const { data: scan, isLoading: scanLoading } = useGetScanJob(scanId as any, {
    query: {
      refetchInterval: (query) => {
        const status = query.state.data?.status;
        return (status === "queued" || status === "running") ? 3000 : false;
      }
    }
  });

  // Engine status polling
  type EngineStatus = { engine: string; status: "pending" | "running" | "done" | "error" | "skipped"; findings: number; started_at?: string; ended_at?: string; error?: string };
  const { data: engines = [] } = useQuery<EngineStatus[]>({
    queryKey: ["/api/scan-jobs", scanId, "engines"],
    queryFn: () => fetch(`/api/scan-jobs/${scanId}/engines`, { credentials: "include" }).then(r => r.json()),
    refetchInterval: (query) => {
      const status = (query.state.data as EngineStatus[] | undefined);
      void status;
      return scan?.status === "running" ? 3000 : false;
    },
  });

  async function handleCompare() {
    if (!scan) return;
    setCompareFetching(true);
    try {
      const r = await fetch(`/api/scan-jobs?target_url=${encodeURIComponent(scan.target_url)}&page_size=20`, { credentials: "include" });
      const data = await r.json();
      const items: Array<{ id: string; created_at: string }> = data?.items ?? [];
      const others = items.filter(s => s.id !== scanId).sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
      if (others.length > 0) {
        setLocation(`/scans/compare?a=${others[0].id}&b=${scanId}`);
      } else {
        toast({ title: "No previous scan found for this target" });
      }
    } catch {
      toast({ title: "Compare failed", variant: "destructive" });
    } finally {
      setCompareFetching(false);
    }
  }

  async function loadDiff() {
    setDiffLoading(true);
    try {
      const r = await fetch(`/api/scan-jobs/${scanId}/diff`, { credentials: "include" });
      const d = await r.json();
      setDiffResult(d);
      setDiffLoaded(true);
    } finally { setDiffLoading(false); }
  }

  const { data: scannerHealth } = useQuery({
    queryKey: ["/api/scanner/health"],
    queryFn: () => fetch("/api/scanner/health", { credentials: "include" }).then(r => r.json()),
    staleTime: 300000,
  });

  const { data: killChains, isLoading: killChainsLoading } = useQuery({
    queryKey: ["/api/scan-jobs", scanId, "kill-chains"],
    queryFn: () =>
      fetch(`/api/scan-jobs/${scanId}/kill-chains`, { credentials: "include" }).then(r => r.json()),
    staleTime: 60000,
  });

  // Fetch all completed scans for comparison selector
  const { data: allScans } = useQuery<{ items: Array<{ id: string; target_url: string; status: string; risk_score: number; findings_count: number; created_at: string }> }>({
    queryKey: ["/api/scan-jobs/all-completed"],
    queryFn: () =>
      fetch("/api/scan-jobs?page_size=50", { credentials: "include" }).then(r => r.json()),
    staleTime: 30000,
  });

  const otherScans = (allScans?.items ?? []).filter(s => s.id !== scanId && s.status === "completed");

  const { data: findings, isLoading: findingsLoading, refetch: refetchFindings } = useGetScanJobFindings(scanId, {
    query: { refetchInterval: 3000 }
  });
  const { data: attackSurface } = useGetScanJobAttackSurface(scanId);

  type LogLine = { kind: "log" | "engine" | "finding" | "error"; text: string; time: string };
  const [sseLog, setSseLog] = useState<LogLine[]>([]);
  const [sseActive, setSseActive] = useState(false);
  const [activeEngine, setActiveEngine] = useState<string | null>(null);
  const sseRef = useRef<EventSource | null>(null);
  const logEndRef = useRef<HTMLDivElement | null>(null);

  const appendLog = (kind: LogLine["kind"], text: string) => {
    const time = new Date().toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
    setSseLog(p => [...p, { kind, text, time }]);
    setTimeout(() => logEndRef.current?.scrollIntoView({ behavior: "smooth" }), 50);
  };

  function startSSE() {
    if (sseRef.current) { sseRef.current.close(); }
    setSseLog([]);
    setSseActive(true);
    setActiveEngine(null);

    const es = new EventSource(`/api/scan-jobs/${scanId}/stream`);
    sseRef.current = es;

    es.addEventListener("log", (e: MessageEvent) => {
      try { const d = JSON.parse(e.data); appendLog("log", d.message ?? ""); } catch { /* */ }
    });
    es.addEventListener("engine", (e: MessageEvent) => {
      try {
        const d = JSON.parse(e.data);
        if (d.status === "scanning") {
          setActiveEngine(d.engine);
          appendLog("engine", `▶ ${d.engine} — ${d.message ?? "scanning"}`);
        } else {
          setActiveEngine(null);
          appendLog("engine", `✓ ${d.engine} — ${d.message ?? "done"}`);
        }
      } catch { /* */ }
    });
    es.addEventListener("finding", (e: MessageEvent) => {
      try {
        const d = JSON.parse(e.data);
        const sev = (d.severity ?? "info").toUpperCase();
        appendLog("finding", `[${sev}] ${d.title} @ ${d.endpoint ?? ""}`);
        refetchFindings();
      } catch { /* */ }
    });
    es.addEventListener("progress", (e: MessageEvent) => {
      try {
        const d = JSON.parse(e.data);
        if (d.progress !== undefined) appendLog("log", `Progress: ${d.progress}%`);
      } catch { /* */ }
    });
    es.addEventListener("complete", (e: MessageEvent) => {
      try {
        const d = JSON.parse(e.data);
        appendLog("log", `✅ ${d.message ?? "Scan complete"}`);
      } catch { /* */ }
      setSseActive(false);
      setActiveEngine(null);
      es.close();
      sseRef.current = null;
      refetchFindings();
    });
    es.addEventListener("error", (e: MessageEvent) => {
      try {
        const d = JSON.parse(e.data);
        appendLog("error", `❌ Error: ${d.message ?? "Scan failed"}`);
      } catch { /* */ }
      setSseActive(false);
      setActiveEngine(null);
      es.close();
      sseRef.current = null;
    });
    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) {
        setSseActive(false);
        setActiveEngine(null);
        sseRef.current = null;
      }
    };
  }

  useEffect(() => {
    if (scan?.status === "running" && !sseRef.current) {
      startSSE();
    }
    if (scan?.status === "completed" || scan?.status === "failed") {
      if (sseRef.current) {
        sseRef.current.close();
        sseRef.current = null;
        setSseActive(false);
      }
      refetchFindings();
    }
  }, [scan?.status]);

  async function runDeduplicate() {
    setDedupeLoading(true);
    setDedupeResult(null);
    try {
      const r = await fetch(`/api/ai/deduplicate/${scanId}`, { method: "POST", credentials: "include" });
      const d = await r.json();
      setDedupeResult(d);
    } catch {
      toast({ title: "Deduplication failed", variant: "destructive" });
    } finally { setDedupeLoading(false); }
  }

  function exportJSON() {
    const blob = new Blob([JSON.stringify({ scan, findings }, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `scan-${scanId}.json`;
    a.click();
  }

  function exportPDF() {
    if (!scan) return;
    const doc = new jsPDF();
    doc.setFontSize(20);
    doc.text("Bug Finder Pro — Scan Report", 14, 22);
    doc.setFontSize(10);
    doc.setTextColor(100);
    doc.text(`Target: ${scan.target_url}`, 14, 32);
    doc.text(`Status: ${scan.status} | Risk Score: ${scan.risk_score}/100`, 14, 38);
    doc.text(`Date: ${format(new Date(scan.created_at), "MMM d, yyyy HH:mm")}`, 14, 44);
    doc.text(`Critical: ${scan.critical_count} | High: ${scan.high_count} | Medium: ${scan.medium_count}`, 14, 50);

    const rows = (Array.isArray(findings) ? findings : []).map((f: Record<string, unknown>) => [
      String(f.title ?? "").slice(0, 50),
      String(f.severity ?? "").toUpperCase(),
      String(f.cvss_score ?? "N/A"),
      String(f.cwe_id ?? ""),
      String(f.endpoint ?? "").slice(0, 40),
    ]);

    autoTable(doc, {
      startY: 58,
      head: [["Title", "Severity", "CVSS", "CWE", "Endpoint"]],
      body: rows,
      styles: { fontSize: 8 },
      headStyles: { fillColor: [109, 40, 217] },
    });

    doc.save(`scan-${scanId}-report.pdf`);
  }

  if (scanLoading) {
    return (
      <div className="space-y-4 p-6">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="h-16 rounded-lg animate-pulse" style={{ background: "hsl(var(--muted))" }} />
        ))}
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="p-8 text-center space-y-3">
        <AlertTriangle className="w-10 h-10 mx-auto text-destructive" />
        <p className="text-destructive font-medium">Scan not found</p>
        <p className="text-sm text-muted-foreground">This scan may have been deleted or the ID is invalid.</p>
      </div>
    );
  }

  const isRunning = scan.status === "running" || scan.status === "queued";

  // Estimated time remaining
  const PROFILE_TOTAL_SECONDS: Record<string, number> = { quick: 120, standard: 300, deep: 900, full: 1800 };
  const totalEstimated = PROFILE_TOTAL_SECONDS[scan.scan_profile] ?? 300;
  const elapsedSec = scan.started_at ? (Date.now() - new Date(scan.started_at).getTime()) / 1000 : 0;
  const remainingSec = scan.status === "running" && typeof scan.progress === "number"
    ? Math.max(0, totalEstimated * (1 - scan.progress / 100))
    : null;
  const etaLabel = remainingSec !== null
    ? remainingSec < 60 ? "< 1m remaining" : `~${Math.ceil(remainingSec / 60)}m remaining`
    : null;
  void elapsedSec;

  // Derive scan phase from active engine for progress label
  const SCAN_PHASES = ["Recon", "Port Scan", "Service Detection", "Vulnerability Scan", "Reporting"];
  const activePhaseIdx = activeEngine
    ? SCAN_PHASES.findIndex(p => activeEngine.toLowerCase().includes(p.toLowerCase().split(" ")[0]))
    : -1;
  const phaseLabel = activePhaseIdx >= 0
    ? `Phase ${activePhaseIdx + 1}/${SCAN_PHASES.length}: ${SCAN_PHASES[activePhaseIdx]}`
    : activeEngine
    ? `Running: ${activeEngine}`
    : "Initializing…";

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-3 mb-1">
            <h1 className="text-3xl font-bold tracking-tight font-mono">{scan.target_url}</h1>
            <Badge variant="outline" className={`capitalize ${
              scan.status === "running" ? "bg-blue-500/10 text-blue-500 border-blue-500/20 animate-pulse" :
              scan.status === "completed" ? "bg-green-500/10 text-green-500 border-green-500/20" :
              scan.status === "failed" ? "bg-destructive/10 text-destructive border-destructive/20" :
              "bg-muted text-muted-foreground"
            }`}>
              {scan.status}
            </Badge>
          </div>
          <p className="text-muted-foreground flex items-center">
            <Clock className="w-4 h-4 mr-1.5" />
            Started {format(new Date(scan.created_at), "MMM d, yyyy HH:mm")}
          </p>
        </div>
        <div className="flex items-center space-x-2 flex-wrap gap-y-2">
          {scan.status === "running" && (
            <Button variant="outline" className="border-yellow-500/40 text-yellow-400 hover:bg-yellow-500/10"
              onClick={() => pauseScan.mutate()} disabled={pauseScan.isPending}>
              <Pause className="w-4 h-4 mr-2" />
              {pauseScan.isPending ? "Pausing…" : "Pause"}
            </Button>
          )}
          {scan.status === "paused" && (
            <Button variant="outline" className="border-green-500/40 text-green-400 hover:bg-green-500/10"
              onClick={() => resumeScan.mutate()} disabled={resumeScan.isPending}>
              <Play className="w-4 h-4 mr-2" />
              {resumeScan.isPending ? "Resuming…" : "Resume"}
            </Button>
          )}
          {isRunning && (
            <Button variant="outline" className="border-orange-500/40 text-orange-400 hover:bg-orange-500/10"
              onClick={() => cancelScan.mutate()} disabled={cancelScan.isPending}>
              <StopCircle className="w-4 h-4 mr-2" />
              {cancelScan.isPending ? "Cancelling…" : "Stop Scan"}
            </Button>
          )}
          <Button variant="outline" onClick={exportJSON}>
            <Download className="w-4 h-4 mr-2" />Export JSON
          </Button>
          <Button variant="outline" onClick={exportPDF} disabled={isRunning}>
            <FileText className="w-4 h-4 mr-2" />PDF Report
          </Button>
          <Button variant="outline" onClick={() => window.open(`/api/reports/${scanId}/pdf`, "_blank")} disabled={isRunning}>
            <Download className="w-4 h-4 mr-2" />Download Report PDF
          </Button>
          <Button variant="outline" onClick={startSSE} disabled={sseActive}>
            {sseActive ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Radio className="w-4 h-4 mr-2" />}
            {sseActive ? "Streaming…" : "Live Stream"}
          </Button>
          <Button variant="outline" onClick={handleCompare} disabled={compareFetching} title="Compare with previous scan for this target">
            {compareFetching ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <GitCompare className="w-4 h-4 mr-2" />}
            Compare
          </Button>
        </div>
      </div>

      {(scannerHealth as any)?.mode === "simulation" && (
        <div className="flex items-center gap-3 p-3 rounded-lg border border-yellow-500/30 bg-yellow-500/10 text-yellow-400 text-sm mb-4">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          <span>Scanner running in <strong>simulation mode</strong> — findings are simulated. Install Nuclei for real vulnerability scanning.</span>
          <a href="/status" className="ml-auto text-xs underline hover:no-underline flex-shrink-0">View Status</a>
        </div>
      )}

      {isRunning && (
        <Card className="border-blue-500/20 bg-blue-500/5">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-blue-500 flex items-center gap-2">
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                {phaseLabel}
              </span>
              <div className="flex items-center gap-3">
                {etaLabel && (
                  <span className="text-xs text-blue-400/70 font-mono">{etaLabel}</span>
                )}
                <span className="text-sm font-mono text-blue-500">{scan.progress ?? 0}%</span>
              </div>
            </div>
            <Progress value={scan.progress ?? 0} className="h-2 [&>div]:bg-blue-500" />
            {/* Phase step indicators */}
            <div className="flex items-center gap-1 mt-2">
              {SCAN_PHASES.map((phase, i) => {
                const pct = scan.progress ?? 0;
                const phaseThreshold = ((i + 1) / SCAN_PHASES.length) * 100;
                const isActive = i === activePhaseIdx;
                const isDone = pct >= phaseThreshold;
                return (
                  <div key={phase} className="flex items-center gap-1 flex-1">
                    <div className="flex-1 flex items-center gap-1">
                      <div className={`h-1 flex-1 rounded-full transition-all ${isDone ? "bg-blue-500" : isActive ? "bg-blue-400/50" : "bg-blue-500/15"}`} />
                      <span className={`text-[9px] font-mono whitespace-nowrap hidden sm:block ${isActive ? "text-blue-400 font-bold" : isDone ? "text-blue-400/60" : "text-blue-400/30"}`}>
                        {phase}
                      </span>
                    </div>
                    {i < SCAN_PHASES.length - 1 && <ChevronRight className="w-2.5 h-2.5 text-blue-500/30 flex-shrink-0" />}
                  </div>
                );
              })}
            </div>
            <p className="text-xs text-blue-400/60 mt-1.5">
              {scan.findings_count > 0
                ? `${scan.findings_count} finding(s) detected so far (${scan.critical_count} critical, ${scan.high_count} high)`
                : "Scanning target for vulnerabilities…"}
            </p>
          </CardContent>
        </Card>
      )}

      {/* WAF Detection Card */}
      {(scan as any).waf_detected === true && (
        <Card className="border-orange-500/30 bg-orange-500/5">
          <CardContent className="pt-4 pb-4">
            <div className="flex items-center gap-3">
              <Badge className="bg-orange-500/20 text-orange-300 border-orange-500/40 hover:bg-orange-500/30">
                WAF: {(scan as any).waf_name || "Detected"}
              </Badge>
              <span className="text-xs text-muted-foreground">
                Bypass attempted · {(scan as any).waf_bypass_count ?? 0} technique(s) succeeded
              </span>
            </div>
          </CardContent>
        </Card>
      )}
      {(scan as any).waf_detected === false && (
        <p className="text-xs text-muted-foreground px-1">No WAF detected</p>
      )}

      {/* Scanner Engines Panel */}
      {(engines.length > 0 || scan.status === "running") && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium">Scanner Engines</CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            {engines.length === 0 && scan.status === "running" ? (
              <div className="flex items-center gap-2 text-sm text-muted-foreground py-2">
                <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
                Waiting for engines to start...
              </div>
            ) : (
              <div className="space-y-2">
                {engines.map((eng) => {
                  const durationSec = eng.started_at && eng.ended_at
                    ? Math.round((new Date(eng.ended_at).getTime() - new Date(eng.started_at).getTime()) / 1000)
                    : null;
                  const displayName = eng.engine.replace(/-/g, " ").replace(/^\w/, c => c.toUpperCase());
                  return (
                    <div key={eng.engine} className="flex items-center gap-3 text-sm py-1.5 border-b border-border/50 last:border-0">
                      <div className="w-4 h-4 shrink-0">
                        {eng.status === "pending" && <Clock className="w-4 h-4 text-muted-foreground" />}
                        {eng.status === "running" && <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />}
                        {eng.status === "done" && <CheckCircle2 className="w-4 h-4 text-green-400" />}
                        {eng.status === "error" && <XCircle className="w-4 h-4 text-red-400" />}
                        {eng.status === "skipped" && <MinusCircle className="w-4 h-4 text-muted-foreground" />}
                      </div>
                      <span className="flex-1 font-medium capitalize">{displayName}</span>
                      {eng.status === "done" && eng.findings > 0 && (
                        <Badge className="bg-green-500/15 text-green-400 border-green-500/30 text-[10px] hover:bg-green-500/25">
                          {eng.findings} findings
                        </Badge>
                      )}
                      {durationSec !== null && (
                        <span className="text-xs text-muted-foreground font-mono">{durationSec}s</span>
                      )}
                      {eng.status === "error" && eng.error && (
                        <span className="text-xs text-red-400 max-w-[200px] truncate" title={eng.error}>{eng.error}</span>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* AI suggestion banner — shown when scan just completed */}
      {scan.status === "completed" && scan.findings_count > 0 && (
        <div className="flex items-center gap-4 px-4 py-3 rounded-lg cursor-pointer group"
          style={{ background: "linear-gradient(135deg, rgba(124,58,237,0.12), rgba(168,85,247,0.08))", border: "1px solid rgba(124,58,237,0.3)" }}
          onClick={() => {
            const el = document.querySelector('[data-value="summary"]') as HTMLElement | null;
            if (el) el.click();
          }}>
          <div className="w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0"
            style={{ background: "rgba(124,58,237,0.2)" }}>
            <Sparkles className="w-4 h-4" style={{ color: "#a855f7" }} />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium" style={{ color: "#a855f7" }}>AI Analysis Ready</p>
            <p className="text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>
              {scan.findings_count} findings discovered — click to generate an AI executive summary &amp; remediation plan.
            </p>
          </div>
          <ChevronRight className="w-4 h-4 flex-shrink-0 opacity-50 group-hover:opacity-100 transition-opacity" style={{ color: "#a855f7" }} />
        </div>
      )}

      {(sseLog.length > 0 || sseActive) && (
        <Card className="border-violet-500/20 bg-violet-500/5">
          <CardHeader className="pb-2 pt-4 px-4">
            <CardTitle className="text-sm flex items-center gap-2">
              {sseActive && <Radio className="w-3.5 h-3.5 text-violet-400 animate-pulse" />}
              Live Scan Stream
              {activeEngine && (
                <span className="text-xs font-normal text-violet-300 bg-violet-500/10 px-2 py-0.5 rounded-full">
                  {activeEngine}
                </span>
              )}
              <button onClick={() => setTerminalDark(v => !v)} className="ml-auto p-1 rounded hover:bg-accent/20 transition-colors">
                {terminalDark ? <Sun className="w-3.5 h-3.5 text-yellow-400" /> : <Moon className="w-3.5 h-3.5 text-violet-400" />}
              </button>
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className={`font-mono text-xs rounded p-3 max-h-64 overflow-y-auto leading-relaxed space-y-0.5 ${terminalDark ? "bg-black/80" : "bg-slate-100 dark:bg-slate-800"}`}>
              {sseActive && sseLog.length === 0 && (
                <span className="text-violet-400/70 animate-pulse">Connecting to scanner…</span>
              )}
              {sseLog.map((line, i) => (
                <div key={i} className={
                  line.kind === "engine" ? "text-cyan-300 font-semibold" :
                  line.kind === "finding" ? (
                    line.text.includes("[CRITICAL]") ? "text-red-400 font-bold" :
                    line.text.includes("[HIGH]") ? "text-orange-400 font-semibold" :
                    line.text.includes("[MEDIUM]") ? "text-yellow-400" :
                    "text-green-400"
                  ) :
                  line.kind === "error" ? "text-red-500" :
                  "text-violet-300/80"
                }>
                  <span className="text-violet-500/50 mr-2 select-none">{line.time}</span>
                  {line.text}
                </div>
              ))}
              <div ref={logEndRef} />
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground font-medium">Risk Score</CardTitle></CardHeader>
          <CardContent>
            <div className={`text-3xl font-bold ${
              scan.risk_score > 80 ? "text-[hsl(var(--critical))]" :
              scan.risk_score > 60 ? "text-[hsl(var(--high))]" :
              scan.risk_score > 30 ? "text-[hsl(var(--medium))]" :
              "text-[hsl(var(--low))]"
            }`}>{scan.risk_score}/100</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground font-medium">Critical</CardTitle></CardHeader>
          <CardContent><div className="text-3xl font-bold text-[hsl(var(--critical))]">{scan.critical_count}</div></CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground font-medium">High</CardTitle></CardHeader>
          <CardContent><div className="text-3xl font-bold text-[hsl(var(--high))]">{scan.high_count}</div></CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground font-medium">Medium</CardTitle></CardHeader>
          <CardContent><div className="text-3xl font-bold text-[hsl(var(--medium))]">{scan.medium_count}</div></CardContent>
        </Card>
      </div>

      <Tabs defaultValue="findings" className="w-full">
        <TabsList className="w-full justify-start border-b border-border rounded-none bg-transparent h-auto p-0 flex-wrap">
          {[
            ["findings", `Findings (${scan.findings_count})`],
            ["diff", "Diff"],
            ["kill-chains", "Kill Chains"],
            ["summary", "AI Summary"],
            ["remediation-plan", "Remediation Plan"],
            ["compare", "AI Compare"],
            ["deduplicate", "Deduplicate"],
            ["surface", "Attack Surface"],
            ["config", "Configuration"],
          ].map(([value, label]) => (
            <TabsTrigger key={value} value={value} data-value={value}
              className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent px-4 py-3 text-xs">
              {value === "diff" ? <><GitCompare className="w-3.5 h-3.5 mr-1.5 inline" />{label}</> :
               value === "kill-chains" ? <><Link2 className="w-3.5 h-3.5 mr-1.5 inline" />{label}</> :
               value === "compare" ? <><GitBranch className="w-3.5 h-3.5 mr-1.5 inline" />{label}</> :
               value === "deduplicate" ? <><Filter className="w-3.5 h-3.5 mr-1.5 inline" />{label}</> :
               label}
            </TabsTrigger>
          ))}
        </TabsList>

        {/* Findings */}
        <TabsContent value="findings" className="pt-6">
          <Card>
            <div className="rounded-md border-0">
              <table className="w-full text-sm text-left">
                <thead className="text-xs text-muted-foreground uppercase bg-muted/50">
                  <tr>
                    <th className="px-4 py-3">Severity</th>
                    <th className="px-4 py-3">Title</th>
                    <th className="px-4 py-3">Category</th>
                    <th className="px-4 py-3">Endpoint</th>
                    <th className="px-4 py-3 text-right">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {findingsLoading ? (
                    <tr><td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">Loading findings...</td></tr>
                  ) : (findings?.items?.length ?? 0) === 0 ? (
                    <tr><td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">
                      {isRunning ? "No findings discovered yet..." : "No vulnerabilities found."}
                    </td></tr>
                  ) : (
                    findings?.items?.map((finding) => (
                      <tr key={finding.id} className="hover:bg-muted/20 cursor-pointer" onClick={() => setLocation(`/findings/${finding.id}`)}>
                        <td className="px-4 py-3 w-24"><SeverityBadge severity={finding.severity} /></td>
                        <td className="px-4 py-3 font-medium">{finding.title}</td>
                        <td className="px-4 py-3 text-muted-foreground text-xs">{finding.category}</td>
                        <td className="px-4 py-3 font-mono text-xs max-w-[200px] truncate" title={finding.endpoint}>{finding.endpoint}</td>
                        <td className="px-4 py-3 text-right">
                          <Badge variant="outline" className="text-[10px] capitalize">{finding.validation_status.replace("_", " ")}</Badge>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </Card>
        </TabsContent>

        {/* Diff */}
        <TabsContent value="diff" className="pt-6">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle>Scan Diff — Delta View</CardTitle>
                <CardDescription>New, fixed, and recurring findings vs. the previous scan</CardDescription>
              </div>
              {!diffLoaded && (
                <Button size="sm" variant="outline" onClick={loadDiff} disabled={diffLoading}>
                  {diffLoading ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Loading…</> : <><GitCompare className="w-4 h-4 mr-2" />Load Diff</>}
                </Button>
              )}
            </CardHeader>
            <CardContent>
              {!diffLoaded ? (
                <div className="py-12 text-center text-muted-foreground text-sm">Click "Load Diff" to compare with the previous scan.</div>
              ) : !diffResult?.previous_scan_id ? (
                <div className="py-12 text-center text-muted-foreground text-sm">No previous scan found for this target.</div>
              ) : (
                <div className="space-y-6">
                  <div className="grid grid-cols-3 gap-4">
                    {[
                      { label: "New", key: "new_findings", color: "text-red-400", bg: "bg-red-500/10" },
                      { label: "Fixed", key: "fixed_findings", color: "text-green-400", bg: "bg-green-500/10" },
                      { label: "Recurring", key: "recurring_findings", color: "text-yellow-400", bg: "bg-yellow-500/10" },
                    ].map(({ label, key, color, bg }) => (
                      <div key={key} className={`rounded-lg p-4 ${bg}`}>
                        <div className={`text-3xl font-bold font-mono ${color}`}>{diffResult[key]?.length ?? 0}</div>
                        <div className="text-xs text-muted-foreground uppercase mt-1">{label} Findings</div>
                      </div>
                    ))}
                  </div>
                  {(["new_findings", "fixed_findings", "recurring_findings"] as const).map((key) => {
                    const items: any[] = diffResult[key] ?? [];
                    if (!items.length) return null;
                    const colors: Record<string, string> = { new_findings: "border-l-red-500", fixed_findings: "border-l-green-500", recurring_findings: "border-l-yellow-500" };
                    const labels: Record<string, string> = { new_findings: "New Findings", fixed_findings: "Fixed Findings", recurring_findings: "Recurring Findings" };
                    return (
                      <div key={key}>
                        <h3 className="text-sm font-semibold mb-2">{labels[key]} ({items.length})</h3>
                        <div className="space-y-1">
                          {items.map((f: any, i: number) => (
                            <div key={i} className={`border-l-2 ${colors[key]} pl-3 py-1.5 flex items-center justify-between rounded-r bg-muted/30`}>
                              <div>
                                <span className="text-sm font-medium">{f.title}</span>
                                {f.endpoint && <span className="text-xs text-muted-foreground ml-2 font-mono">{f.endpoint}</span>}
                              </div>
                              <Badge className="text-[10px] uppercase ml-2 shrink-0">{f.severity}</Badge>
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Kill Chains */}
        <TabsContent value="kill-chains" className="pt-6">
          <Card>
            <CardHeader>
              <CardTitle>Kill Chain Correlation</CardTitle>
              <CardDescription>Multi-step attack paths from finding combinations</CardDescription>
            </CardHeader>
            <CardContent>
              {killChainsLoading ? (
                <div className="py-8 text-center text-muted-foreground text-sm">Analyzing findings…</div>
              ) : !killChains?.chains?.length ? (
                <div className="py-12 text-center text-muted-foreground text-sm">No kill chain patterns detected.</div>
              ) : (
                <div className="space-y-4">
                  {killChains.chains.map((chain: any, i: number) => (
                    <div key={i} className="border border-orange-500/30 rounded-lg p-4 bg-orange-500/5">
                      <div className="flex items-start justify-between mb-2">
                        <div>
                          <h3 className="font-semibold text-orange-300">{chain.name}</h3>
                          <p className="text-xs text-muted-foreground mt-0.5">{chain.description}</p>
                        </div>
                        <Badge className="bg-orange-500/20 text-orange-300 border-orange-500/30 text-[10px] uppercase shrink-0 ml-3">{chain.severity}</Badge>
                      </div>
                      <div className="mt-3">
                        <p className="text-xs text-muted-foreground mb-1.5">Contributing findings:</p>
                        <div className="flex flex-wrap gap-1.5">
                          {chain.finding_ids.map((fid: string) => (
                            <button key={fid} onClick={() => setLocation(`/findings/${fid}`)}
                              className="text-[10px] font-mono bg-muted hover:bg-muted/80 px-2 py-0.5 rounded border border-border transition-colors">
                              {fid.slice(0, 8)}
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* AI Summary */}
        <TabsContent value="summary" className="pt-6">
          <ScanAiPanel
            fetchFn={() => fetch(`/api/ai/scan-summary/${scanId}`, { method: "POST", credentials: "include" })}
            title="AI Executive Summary"
            description="Security posture assessment, critical issues, and recommended actions"
            buttonLabel="Generate Summary"
            icon={<Activity className="w-4 h-4" />}
            emptyText='Click "Generate Summary" to get an AI-powered executive assessment of this scan.'
            disabled={isRunning}
            disabledReason="Wait for the scan to complete before generating a summary."
          />
        </TabsContent>

        {/* Remediation Plan */}
        <TabsContent value="remediation-plan" className="pt-6">
          <ScanAiPanel
            fetchFn={() => fetch(`/api/ai/remediation-plan/${scanId}`, { method: "POST", credentials: "include" })}
            title="Remediation Sprint Plan"
            description="Prioritized engineering sprint plan covering all findings with effort estimates"
            buttonLabel="Generate Plan"
            icon={<FileText className="w-4 h-4" />}
            emptyText='Click "Generate Plan" to create a prioritized sprint plan for remediating all findings.'
            disabled={isRunning}
            disabledReason="Complete the scan first to generate a remediation plan."
          />
        </TabsContent>

        {/* AI Compare */}
        <TabsContent value="compare" className="pt-6 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><GitBranch className="w-5 h-5 text-violet-400" />AI Scan Comparison</CardTitle>
              <CardDescription>Compare this scan against another to get an AI narrative of what changed, improved, or regressed</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex gap-3 mb-4">
                <Select value={compareTargetId} onValueChange={setCompareTargetId}>
                  <SelectTrigger className="flex-1">
                    <SelectValue placeholder="Select a scan to compare against…" />
                  </SelectTrigger>
                  <SelectContent>
                    {otherScans.length === 0 ? (
                      <SelectItem value="none" disabled>No other completed scans available</SelectItem>
                    ) : otherScans.map(s => (
                      <SelectItem key={s.id} value={s.id}>
                        {s.target_url.replace(/https?:\/\//, "").slice(0, 35)} — Risk: {s.risk_score}/100 — {format(new Date(s.created_at), "MMM d")}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              {compareTargetId && compareTargetId !== "none" && (
                <ScanAiPanel
                  fetchFn={() => fetch(`/api/ai/scan-compare/${scanId}/${compareTargetId}`, { method: "POST", credentials: "include" })}
                  title="Comparison Analysis"
                  description="Risk trend, new vulnerabilities introduced, remediation progress, and persistent issues"
                  buttonLabel="Compare Scans"
                  icon={<GitBranch className="w-4 h-4" />}
                  emptyText='Click "Compare Scans" to generate a detailed comparison narrative.'
                />
              )}
              {!compareTargetId && (
                <div className="py-8 text-center text-muted-foreground text-sm">Select a scan above to enable comparison.</div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Deduplication */}
        <TabsContent value="deduplicate" className="pt-6">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle className="flex items-center gap-2"><Filter className="w-5 h-5 text-violet-400" />AI Finding Deduplication</CardTitle>
                <CardDescription>Identify duplicate or near-duplicate findings that describe the same vulnerability</CardDescription>
              </div>
              <Button size="sm" variant="outline" onClick={runDeduplicate} disabled={dedupeLoading || isRunning}>
                {dedupeLoading ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Analyzing…</> : <>Detect Duplicates</>}
              </Button>
            </CardHeader>
            <CardContent>
              {!dedupeResult && !dedupeLoading && (
                <div className="py-12 text-center text-muted-foreground text-sm">
                  {isRunning ? "Complete the scan first." : 'Click "Detect Duplicates" to find semantically similar findings that may be the same vulnerability reported multiple times.'}
                </div>
              )}
              {dedupeResult && (
                dedupeResult.duplicates.length === 0 ? (
                  <div className="py-8 text-center">
                    <CheckCircle2 className="w-8 h-8 text-green-400 mx-auto mb-2" />
                    <p className="text-sm text-muted-foreground">No duplicate findings detected. All findings appear to be unique.</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <p className="text-xs text-muted-foreground">{dedupeResult.duplicates.length} duplicate group(s) found — consider merging or dismissing lower-quality duplicates</p>
                    {dedupeResult.duplicates.map((group, i) => (
                      <div key={i} className="border border-yellow-500/30 rounded-lg p-4 bg-yellow-500/5">
                        <p className="text-xs text-yellow-300 mb-3 font-medium">Group {i + 1}: {group.reason}</p>
                        <div className="space-y-2">
                          {group.findings.map(f => (
                            <div key={f.id}
                              className="flex items-center justify-between p-2 rounded border border-border bg-muted/30 cursor-pointer hover:bg-muted/50 transition-colors"
                              onClick={() => setLocation(`/findings/${f.id}`)}>
                              <div className="flex items-center gap-2 min-w-0">
                                <SeverityBadge severity={f.severity} />
                                <span className="text-sm font-medium truncate">{f.title}</span>
                              </div>
                              <span className="text-xs font-mono text-muted-foreground ml-2 shrink-0">{f.endpoint.slice(0, 40)}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                )
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Attack Surface */}
        <TabsContent value="surface" className="pt-6">
          <Card>
            <CardHeader>
              <CardTitle>Attack Surface Map</CardTitle>
              <CardDescription>Discovered nodes and relationships</CardDescription>
            </CardHeader>
            <CardContent>
              {attackSurface ? (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                    <div className="p-4 bg-muted/50 rounded-md">
                      <div className="text-2xl font-bold">{attackSurface.nodes.filter(n => n.type === "domain").length}</div>
                      <div className="text-xs text-muted-foreground uppercase">Domains</div>
                    </div>
                    <div className="p-4 bg-muted/50 rounded-md">
                      <div className="text-2xl font-bold">{attackSurface.nodes.filter(n => n.type === "endpoint").length}</div>
                      <div className="text-xs text-muted-foreground uppercase">Endpoints</div>
                    </div>
                    <div className="p-4 bg-muted/50 rounded-md">
                      <div className="text-2xl font-bold">{attackSurface.nodes.filter(n => n.type === "parameter").length}</div>
                      <div className="text-xs text-muted-foreground uppercase">Parameters</div>
                    </div>
                    <div className="p-4 bg-muted/50 rounded-md">
                      <div className="text-2xl font-bold">{attackSurface.edges.length}</div>
                      <div className="text-xs text-muted-foreground uppercase">Connections</div>
                    </div>
                  </div>
                  <div className="border border-border rounded-md overflow-hidden">
                    <table className="w-full text-sm">
                      <thead className="bg-muted/50 text-xs uppercase text-muted-foreground">
                        <tr>
                          <th className="px-4 py-2 text-left">Node Type</th>
                          <th className="px-4 py-2 text-left">Identifier</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border">
                        {attackSurface.nodes.slice(0, 20).map(node => (
                          <tr key={node.id}>
                            <td className="px-4 py-2"><Badge variant="outline" className="text-[10px]">{node.type}</Badge></td>
                            <td className="px-4 py-2 font-mono text-xs">{node.label}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {attackSurface.nodes.length > 20 && (
                      <div className="p-2 text-center text-xs text-muted-foreground bg-muted/20 border-t border-border">
                        Showing 20 of {attackSurface.nodes.length} nodes
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="text-center py-12 text-muted-foreground">
                  {isRunning ? "Mapping attack surface..." : "No attack surface data available."}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Config */}
        <TabsContent value="config" className="pt-6">
          <Card>
            <CardHeader><CardTitle>Scan Configuration</CardTitle></CardHeader>
            <CardContent>
              <dl className="grid grid-cols-1 md:grid-cols-2 gap-x-4 gap-y-6 text-sm">
                <div>
                  <dt className="text-muted-foreground font-medium mb-1">Target URL</dt>
                  <dd className="font-mono">{scan.target_url}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground font-medium mb-1">Profile</dt>
                  <dd className="uppercase tracking-wide">{scan.scan_profile}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground font-medium mb-1">Engines Used</dt>
                  <dd className="flex gap-2 flex-wrap">
                    {scan.scanner_engines.map(engine => (
                      <Badge key={engine} variant="secondary" className="capitalize">{engine}</Badge>
                    ))}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground font-medium mb-1">Options</dt>
                  <dd className="space-y-1">
                    <div className="flex items-center">
                      {scan.validation_enabled ? <CheckCircle2 className="w-4 h-4 text-green-500 mr-2" /> : <XCircle className="w-4 h-4 text-muted-foreground mr-2" />}
                      <span>Validation</span>
                    </div>
                    <div className="flex items-center">
                      {scan.fuzzing_enabled ? <CheckCircle2 className="w-4 h-4 text-green-500 mr-2" /> : <XCircle className="w-4 h-4 text-muted-foreground mr-2" />}
                      <span>Active Fuzzing</span>
                    </div>
                    <div className="flex items-center">
                      {scan.bug_bounty_mode ? <CheckCircle2 className="w-4 h-4 text-green-500 mr-2" /> : <XCircle className="w-4 h-4 text-muted-foreground mr-2" />}
                      <span>Bug Bounty Mode</span>
                    </div>
                  </dd>
                </div>
              </dl>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

