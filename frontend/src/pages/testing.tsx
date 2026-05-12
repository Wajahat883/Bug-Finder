import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Play, Square, RefreshCw, CheckCircle2, XCircle, AlertTriangle,
  Clock, ChevronRight, ChevronDown, Terminal, Shield, Database,
  Timer, LayoutDashboard, GitCompare, Smartphone, Lock,
  BarChart3, Activity, Zap,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

const API = "/api/tests";

interface TestSuiteInfo {
  id: string;
  category: string;
  label: string;
  description: string;
  icon: string;
  testCount: number;
  tests: { id: string; name: string; description: string; tags?: string[] }[];
}

interface TestResult {
  id: string;
  name: string;
  category: string;
  status: "pass" | "fail" | "warn" | "error" | "skipped";
  duration: number;
  message: string;
  details?: string;
  suggestion?: string;
  evidence?: Record<string, unknown>;
}

interface TestRunSummary {
  total: number;
  pass: number;
  fail: number;
  warn: number;
  error: number;
  skipped: number;
  duration: number;
}

interface TestRun {
  runId: string;
  status: string;
  summary: TestRunSummary;
  startedAt: string;
  completedAt?: string;
  suites: string[];
  results?: TestResult[];
}

const ICON_MAP: Record<string, React.ElementType> = {
  Lock, Terminal, Shield, Database, Timer, LayoutDashboard, GitCompare, Smartphone, "ShieldAlert": Shield,
};
const STATUS_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  pass:   { bg: "rgba(34,197,94,0.08)", text: "#22c55e", border: "rgba(34,197,94,0.3)" },
  fail:   { bg: "rgba(239,68,68,0.08)", text: "#ef4444", border: "rgba(239,68,68,0.3)" },
  warn:   { bg: "rgba(250,204,21,0.08)", text: "#facc15", border: "rgba(250,204,21,0.3)" },
  error:  { bg: "rgba(239,68,68,0.12)", text: "#f87171", border: "rgba(239,68,68,0.4)" },
  skipped:{ bg: "rgba(156,163,175,0.05)", text: "#9ca3af", border: "rgba(156,163,175,0.2)" },
};

export default function TestingDashboard() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [selectedSuites, setSelectedSuites] = useState<Set<string>>(new Set());
  const [runId, setRunId] = useState<string | null>(null);
  const [streamResults, setStreamResults] = useState<TestResult[]>([]);
  const [runStatus, setRunStatus] = useState<string>("idle");
  const [runSummary, setRunSummary] = useState<TestRunSummary | null>(null);
  const [selectAll, setSelectAll] = useState(false);

  const { data: suites, isLoading } = useQuery<TestSuiteInfo[]>({
    queryKey: ["test-suites"],
    queryFn: () => fetch(API + "/suites", { credentials: "include" }).then(r => r.json()),
  });

  const runMutation = useMutation({
    mutationFn: (suiteIds: string[]) =>
      fetch(API + "/run", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ suiteIds }),
      }).then(r => r.json()),
    onSuccess: (data: TestRun) => {
      setRunId(data.runId);
      setRunStatus("running");
      setStreamResults([]);
      setRunSummary(null);
      qc.invalidateQueries({ queryKey: ["test-runs"] });
    },
    onError: () => toast({ title: "Failed to start tests", variant: "destructive" }),
  });

  useEffect(() => {
    if (!runId || runStatus !== "running") return;
    const es = new EventSource(`${API}/runs/${runId}/stream`, { withCredentials: true } as EventSourceInit);

    es.addEventListener("test-result", (e) => {
      const data = JSON.parse(e.data) as { result: TestResult };
      setStreamResults(prev => [...prev, data.result]);
    });
    es.addEventListener("test-event", (e) => {
      const data = JSON.parse(e.data) as Record<string, unknown>;
      if (data.type === "suite-start" || data.type === "suite-end" || data.type === "test-start") {
        // progress updates
      }
    });
    es.addEventListener("complete", (e) => {
      const data = JSON.parse(e.data) as TestRun;
      setStreamResults(data.results ?? []);
      setRunSummary(data.summary);
      setRunStatus("completed");
      qc.invalidateQueries({ queryKey: ["test-runs"] });
      es.close();
      toast({ title: `Tests complete — ${data.summary.pass} passed, ${data.summary.fail} failed` });
    });
    es.onerror = () => {
      setRunStatus("error");
      es.close();
    };

    return () => es.close();
  }, [runId, runStatus]);

  function toggleSuite(id: string) {
    const next = new Set(selectedSuites);
    if (next.has(id)) next.delete(id); else next.add(id);
    setSelectedSuites(next);
  }

  function handleSelectAll() {
    if (suites && suites.length > 0) {
      if (selectAll) {
        setSelectedSuites(new Set());
      } else {
        setSelectedSuites(new Set(suites.map(s => s.id)));
      }
      setSelectAll(!selectAll);
    }
  }

  function handleRun() {
    const ids = selectedSuites.size > 0 ? [...selectedSuites] : (suites?.map(s => s.id) ?? []);
    runMutation.mutate(ids);
  }

  const totalTests = suites?.reduce((sum, s) => sum + s.testCount, 0) ?? 0;
  const selectedTests = suites?.reduce((sum, s) => selectedSuites.has(s.id) ? sum + s.testCount : sum, 0) ?? 0;

  return (
    <div className="max-w-6xl space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Testing Dashboard</h1>
          <p className="text-muted-foreground mt-1">
            Run comprehensive test suites directly within the application
          </p>
        </div>
        <button
          onClick={handleRun}
          disabled={runMutation.isPending || runStatus === "running"}
          className="flex items-center gap-2 px-5 py-2.5 rounded-lg text-white font-semibold text-sm transition-all disabled:opacity-50"
          style={{ background: "linear-gradient(135deg, #7c3aed, #8b5cf6)", boxShadow: "0 4px 15px rgba(124,58,237,0.3)" }}
        >
          {runStatus === "running" ? (
            <><RefreshCw size={16} className="animate-spin" /> Running…</>
          ) : (
            <><Play size={16} /> Run Tests ({selectedTests || totalTests})</>
          )}
        </button>
      </div>

      {/* Summary bar when run is in progress or completed */}
      {runSummary && (
        <div className="rounded-xl p-4 flex items-center gap-6 flex-wrap"
          style={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))" }}>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full" style={{ background: runStatus === "completed" ? "#22c55e" : "#facc15" }} />
            <span className="text-sm font-semibold">{runStatus === "completed" ? "Completed" : "Running"}</span>
          </div>
          <div className="flex items-center gap-1 text-sm" style={{ color: "#22c55e" }}>
            <CheckCircle2 size={14} /> {runSummary.pass} passed
          </div>
          <div className="flex items-center gap-1 text-sm" style={{ color: "#ef4444" }}>
            <XCircle size={14} /> {runSummary.fail} failed
          </div>
          <div className="flex items-center gap-1 text-sm" style={{ color: "#facc15" }}>
            <AlertTriangle size={14} /> {runSummary.warn} warnings
          </div>
          <div className="flex items-center gap-1 text-sm" style={{ color: "#9ca3af" }}>
            <Activity size={14} /> {Math.round(runSummary.duration)}ms
          </div>
          <div className="flex-1 bg-muted rounded-full h-2 overflow-hidden">
            <div className="h-full flex">
              <div style={{ width: `${(runSummary.pass / Math.max(runSummary.total, 1)) * 100}%`, background: "#22c55e" }} />
              <div style={{ width: `${(runSummary.fail / Math.max(runSummary.total, 1)) * 100}%`, background: "#ef4444" }} />
              <div style={{ width: `${(runSummary.warn / Math.max(runSummary.total, 1)) * 100}%`, background: "#facc15" }} />
            </div>
          </div>
        </div>
      )}

      {/* Suites grid */}
      <div className="space-y-3">
        <div className="flex items-center gap-3 mb-2">
          <button
            onClick={handleSelectAll}
            className="text-xs px-3 py-1 rounded-md border transition-colors hover:bg-accent"
            style={{ borderColor: "hsl(var(--border))", color: "hsl(var(--muted-foreground))" }}
          >
            {selectAll ? "Deselect All" : "Select All Suites"}
          </button>
        </div>

        {isLoading ? (
          <div className="text-center py-12 text-muted-foreground">Loading test suites…</div>
        ) : (
          <div className="grid gap-3">
            {(suites ?? []).map((suite) => {
              const Icon = ICON_MAP[suite.icon] ?? Terminal;
              const isChecked = selectedSuites.has(suite.id);
              const isOpen = expanded[suite.id];

              return (
                <div key={suite.id} className="rounded-xl overflow-hidden"
                  style={{ background: "hsl(var(--card))", border: `1px solid ${isChecked ? "rgba(124,58,237,0.4)" : "hsl(var(--border))"}` }}>
                  <div className="flex items-center p-4 cursor-pointer select-none"
                    onClick={() => setExpanded(p => ({ ...p, [suite.id]: !p[suite.id] }))}>
                    <input
                      type="checkbox"
                      checked={isChecked}
                      onChange={(e) => { e.stopPropagation(); toggleSuite(suite.id); }}
                      className="w-4 h-4 rounded accent-primary mr-3"
                    />
                    <div className="w-8 h-8 rounded-lg flex items-center justify-center mr-3"
                      style={{ background: "hsl(var(--primary)/0.1)", color: "hsl(var(--primary))" }}>
                      <Icon size={16} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h3 className="font-semibold text-sm">{suite.label}</h3>
                      <p className="text-xs text-muted-foreground truncate">{suite.description}</p>
                    </div>
                    <span className="text-xs px-2 py-0.5 rounded-full bg-muted text-muted-foreground mr-2">
                      {suite.testCount} tests
                    </span>
                    {isOpen ? <ChevronDown size={16} className="text-muted-foreground" /> : <ChevronRight size={16} className="text-muted-foreground" />}
                  </div>

                  {isOpen && (
                    <div className="px-4 pb-3 space-y-1.5" style={{ borderTop: "1px solid hsl(var(--border))" }}>
                      {suite.tests.map((test) => {
                        const streamResult = streamResults.find(r => r.id === test.id);
                        const st = streamResult?.status;
                        return (
                          <div key={test.id} className="flex items-center gap-3 py-2 px-3 rounded-md text-sm"
                            style={{ background: streamResult ? (STATUS_COLORS[st ?? "skipped"]?.bg ?? "transparent") : "transparent" }}>
                            {streamResult ? (
                              st === "pass" ? <CheckCircle2 size={14} style={{ color: "#22c55e" }} /> :
                              st === "fail" || st === "error" ? <XCircle size={14} style={{ color: "#ef4444" }} /> :
                              st === "warn" ? <AlertTriangle size={14} style={{ color: "#facc15" }} /> :
                              <Clock size={14} className="text-muted-foreground" />
                            ) : (
                              <div className="w-3.5 h-3.5 rounded-full border" style={{ borderColor: "hsl(var(--border))" }} />
                            )}
                            <span className="flex-1">{test.name}</span>
                            <span className="text-xs text-muted-foreground">{test.description.slice(0, 60)}…</span>
                            {streamResult && (
                              <span className="text-xs text-muted-foreground">{streamResult.duration}ms</span>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Results detail after run */}
      {streamResults.length > 0 && runStatus === "completed" && (
        <div className="space-y-3">
          <h2 className="text-xl font-bold">Detailed Results</h2>
          {streamResults.filter(r => r.status !== "pass").map((result) => {
            const colors = STATUS_COLORS[result.status] ?? STATUS_COLORS.skipped;
            return (
              <div key={result.id} className="p-4 rounded-xl"
                style={{ background: colors.bg, border: `1px solid ${colors.border}` }}>
                <div className="flex items-start gap-3">
                  {result.status === "fail" || result.status === "error" ? (
                    <XCircle size={18} style={{ color: colors.text }} className="mt-0.5 flex-shrink-0" />
                  ) : (
                    <AlertTriangle size={18} style={{ color: colors.text }} className="mt-0.5 flex-shrink-0" />
                  )}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-sm" style={{ color: "hsl(var(--foreground))" }}>{result.name}</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded uppercase" style={{ background: colors.border, color: colors.text }}>
                        {result.status}
                      </span>
                      <span className="text-xs text-muted-foreground">{result.duration}ms</span>
                    </div>
                    <p className="text-sm mt-1" style={{ color: "hsl(var(--foreground))" }}>{result.message}</p>
                    {result.suggestion && (
                      <p className="text-xs mt-2 px-2 py-1 rounded" style={{ background: "rgba(255,255,255,0.03)", color: "hsl(var(--muted-foreground))" }}>
                        Suggestion: {result.suggestion}
                      </p>
                    )}
                    {result.evidence && (
                      <details className="mt-2">
                        <summary className="text-xs text-muted-foreground cursor-pointer hover:text-foreground">Evidence</summary>
                        <pre className="text-[10px] mt-1 p-2 rounded overflow-x-auto" style={{ background: "hsl(var(--muted))", color: "hsl(var(--muted-foreground))" }}>
                          {JSON.stringify(result.evidence, null, 2)}
                        </pre>
                      </details>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
          {streamResults.every(r => r.status === "pass") && (
            <div className="text-center py-8 rounded-xl" style={{ background: "rgba(34,197,94,0.05)", border: "1px solid rgba(34,197,94,0.15)" }}>
              <CheckCircle2 size={48} className="mx-auto mb-2" style={{ color: "#22c55e" }} />
              <p className="text-lg font-semibold" style={{ color: "#22c55e" }}>All {streamResults.length} tests passed!</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
