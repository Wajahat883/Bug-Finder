import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Shield, Users, ScrollText, Webhook, Settings, ArrowRight,
  Activity, Lock, AlertTriangle, BarChart3,
  Play, RefreshCw, CheckCircle2, XCircle, Clock,
  Terminal, FlaskConical, ChevronDown, ChevronRight,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface DashboardStats {
  totalUsers: number;
  totalScans: number;
  totalFindings: number;
  activeScans: number;
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

interface TestResult {
  id: string;
  name: string;
  category: string;
  status: "pass" | "fail" | "warn" | "error" | "skipped";
  duration: number;
  message: string;
  suggestion?: string;
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

interface TestSuiteInfo {
  id: string;
  label: string;
  testCount: number;
}

const STATUS_COLORS: Record<string, string> = {
  pass: "#22c55e", fail: "#ef4444", warn: "#facc15", error: "#f87171", skipped: "#9ca3af",
};

export default function AdminPanel() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const qc = useQueryClient();
  const [runStatus, setRunStatus] = useState<string>("idle");
  const [liveResults, setLiveResults] = useState<TestResult[]>([]);
  const [runSummary, setRunSummary] = useState<TestRunSummary | null>(null);
  const [expandedCategory, setExpandedCategory] = useState<string | null>(null);
  const [viewingRunId, setViewingRunId] = useState<string | null>(null);

  const { data: stats, isLoading: statsLoading } = useQuery<DashboardStats>({
    queryKey: ["/api/admin/stats"],
    queryFn: () => fetch("/api/admin/stats", { credentials: "include" }).then(r => r.json()),
    staleTime: 30000,
  });

  const { data: suites } = useQuery<TestSuiteInfo[]>({
    queryKey: ["test-suites"],
    queryFn: () => fetch("/api/tests/suites", { credentials: "include" }).then(r => r.json()),
    staleTime: 60000,
  });

  const { data: testHistory } = useQuery<TestRun[]>({
    queryKey: ["test-runs"],
    queryFn: () => fetch("/api/tests/runs?limit=3", { credentials: "include" }).then(r => r.json()),
    staleTime: 10000,
  });

  const lastRun = testHistory?.[0];

  const runMutation = useMutation({
    mutationFn: () =>
      fetch("/api/tests/run", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ suiteIds: suites?.map(s => s.id) ?? [] }),
      }).then(r => r.json()),
    onSuccess: (data: TestRun) => {
      setViewingRunId(data.runId);
      setRunStatus("running");
      setLiveResults([]);
      setRunSummary(null);
    },
    onError: () => toast({ title: "Failed to start tests", variant: "destructive" }),
  });

  useEffect(() => {
    if (!viewingRunId || runStatus !== "running") return;
    const es = new EventSource(`/api/tests/runs/${viewingRunId}/stream`, { withCredentials: true } as EventSourceInit);

    es.addEventListener("test-result", (e) => {
      const data = JSON.parse(e.data) as { result: TestResult };
      setLiveResults(prev => [...prev, data.result]);
    });

    es.addEventListener("complete", (e) => {
      const data = JSON.parse(e.data) as TestRun;
      setLiveResults(data.results ?? []);
      setRunSummary(data.summary);
      setRunStatus("completed");
      qc.invalidateQueries({ queryKey: ["test-runs"] });
      es.close();
      const s = data.summary;
      toast({ title: `Tests Done — ${s.pass}P ${s.fail}F ${s.warn}W` });
    });

    es.onerror = () => { setRunStatus("error"); es.close(); };

    return () => es.close();
  }, [viewingRunId, runStatus]);

  const displayResults = runStatus === "running" || runStatus === "completed" ? liveResults : lastRun?.results ?? [];

  const groupedResults = displayResults.reduce<Record<string, TestResult[]>>((acc, r) => {
    if (!acc[r.category]) acc[r.category] = [];
    acc[r.category].push(r);
    return acc;
  }, {});

  const adminModules = [
    { title: "User Management", description: "Manage platform users, roles, and account status.", icon: Users, href: "/admin/users", color: "#8b5cf6", bg: "rgba(139,92,246,0.1)" },
    { title: "Audit Log", description: "Security audit trail with user actions and events.", icon: ScrollText, href: "/audit-log", color: "#22d3ee", bg: "rgba(34,211,238,0.1)" },
    { title: "Integrations", description: "Configure GitHub, Slack, webhooks, and API keys.", icon: Webhook, href: "/integrations", color: "#f97316", bg: "rgba(249,115,22,0.1)" },
    { title: "API Keys", description: "Manage system API keys for programmatic access.", icon: Terminal, href: "/api-keys", color: "#ec4899", bg: "rgba(236,72,153,0.1)" },
    { title: "Testing Suite", description: "Run full test suite — auth, API, security, performance, regression.", icon: FlaskConical, href: "/testing", color: "#a855f7", bg: "rgba(168,85,247,0.1)" },
    { title: "Platform Settings", description: "Global configuration, AI models, and SMTP.", icon: Settings, href: "/settings", color: "#34d399", bg: "rgba(52,211,153,0.1)" },
  ];

  const quickStats = [
    { label: "Total Users", value: stats?.totalUsers ?? 0, icon: Users, color: "#8b5cf6" },
    { label: "Total Scans", value: stats?.totalScans ?? 0, icon: Activity, color: "#22d3ee" },
    { label: "Total Findings", value: stats?.totalFindings ?? 0, icon: AlertTriangle, color: "#f97316" },
    { label: "Tests Passed", value: lastRun?.summary?.pass ?? runSummary?.pass ?? 0, icon: CheckCircle2, color: "#22c55e" },
  ];

  const totalTests = suites?.reduce((sum, s) => sum + s.testCount, 0) ?? 47;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
            <Shield className="w-7 h-7 text-purple-400" />
            Admin Panel
          </h1>
          <p className="text-muted-foreground mt-1">Central dashboard for platform administration and oversight.</p>
        </div>
        <div className="flex items-center gap-3">
          {lastRun && (
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs" style={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))" }}>
              <span className="text-muted-foreground">Last run:</span>
              <span style={{ color: lastRun.summary.fail > 0 ? "#ef4444" : "#22c55e" }}>
                {lastRun.summary.pass}/{lastRun.summary.total} passed
              </span>
              <span className="text-muted-foreground">
                {Math.round(lastRun.summary.duration)}ms
              </span>
            </div>
          )}
          <button
            onClick={() => runMutation.mutate()}
            disabled={runMutation.isPending || runStatus === "running"}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-white font-semibold text-sm transition-all disabled:opacity-50"
            style={{ background: "linear-gradient(135deg, #7c3aed, #8b5cf6)", boxShadow: "0 4px 15px rgba(124,58,237,0.3)" }}
          >
            {runStatus === "running" ? (
              <><RefreshCw size={14} className="animate-spin" /> Running {totalTests} Tests…</>
            ) : (
              <><Play size={14} /> Run All {totalTests} Tests</>
            )}
          </button>
        </div>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {quickStats.map((stat) => {
          const Icon = stat.icon;
          return (
            <Card key={stat.label} className="border-border/60">
              <CardContent className="p-5">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs text-muted-foreground uppercase font-semibold tracking-wider">{stat.label}</p>
                    <p className="text-2xl font-bold mt-1">{statsLoading && stat.label !== "Tests Passed" ? "—" : stat.value}</p>
                  </div>
                  <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ background: stat.color + "15" }}>
                    <Icon className="w-5 h-5" style={{ color: stat.color }} />
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Live test progress bar */}
      {(runStatus === "running" || (runSummary && runStatus === "completed")) && (
        <Card className="border-border/60 overflow-hidden">
          <CardContent className="p-0">
            <div className="px-5 py-3 flex items-center gap-4 border-b border-border/60">
              <div className="w-2.5 h-2.5 rounded-full" style={{ background: runStatus === "completed" ? "#22c55e" : "#facc15" }} />
              <span className="text-sm font-semibold">
                {runStatus === "completed" ? "Test Run Complete" : `Running Tests (${liveResults.length} complete)`}
              </span>
              <div className="flex-1 bg-muted rounded-full h-1.5 overflow-hidden">
                <div className="h-full flex transition-all duration-300"
                  style={{
                    width: runStatus === "completed" ? "100%" : `${Math.min((liveResults.length / totalTests) * 100, 95)}%`,
                    background: "linear-gradient(90deg, #7c3aed, #a78bfa)",
                  }}
                />
              </div>
              {runSummary && (
                <div className="flex items-center gap-3 text-xs">
                  <span style={{ color: "#22c55e" }}>{runSummary.pass}P</span>
                  <span style={{ color: "#ef4444" }}>{runSummary.fail}F</span>
                  <span style={{ color: "#facc15" }}>{runSummary.warn}W</span>
                </div>
              )}
            </div>

            {/* Results by category */}
            <div className="divide-y divide-border/40">
              {Object.entries(groupedResults).map(([category, results]) => {
                const isOpen = expandedCategory === category;
                const catFails = results.filter(r => r.status === "fail" || r.status === "error" || r.status === "warn");
                const catPasses = results.filter(r => r.status === "pass");

                return (
                  <div key={category}>
                    <button
                      onClick={() => setExpandedCategory(isOpen ? null : category)}
                      className="w-full flex items-center px-5 py-3 hover:bg-accent/30 transition-colors text-left"
                    >
                      <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground w-24 flex-shrink-0">{category}</span>
                      <div className="flex items-center gap-2 flex-1">
                        <span className="text-xs" style={{ color: "#22c55e" }}>{catPasses.length}P</span>
                        {catFails.length > 0 && <span className="text-xs" style={{ color: "#ef4444" }}>{catFails.length}F</span>}
                      </div>
                      <span className="text-xs text-muted-foreground mr-2">{results.length} tests</span>
                      {isOpen ? <ChevronDown size={14} className="text-muted-foreground" /> : <ChevronRight size={14} className="text-muted-foreground" />}
                    </button>

                    {isOpen && (
                      <div className="px-5 pb-3 space-y-1">
                        {results.map((result) => (
                          <div key={result.id} className="flex items-center gap-2 py-1.5 px-2 rounded text-xs"
                            style={{ background: result.status !== "pass" ? `rgba(${result.status === "fail" || result.status === "error" ? "239,68,68" : "250,204,21"},0.06)` : "transparent" }}>
                            {result.status === "pass" ? <CheckCircle2 size={12} style={{ color: "#22c55e" }} /> :
                             result.status === "fail" || result.status === "error" ? <XCircle size={12} style={{ color: "#ef4444" }} /> :
                             result.status === "warn" ? <AlertTriangle size={12} style={{ color: "#facc15" }} /> :
                             <Clock size={12} className="text-muted-foreground" />}
                            <span className="flex-1 font-medium">{result.name}</span>
                            <span className="text-muted-foreground">{result.message}</span>
                            <span className="text-muted-foreground w-12 text-right">{result.duration}ms</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {displayResults.length === 0 && (
              <div className="px-5 py-8 text-center text-xs text-muted-foreground">
                No test results yet. Click "Run All Tests" to start.
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Admin Modules Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {adminModules.map((mod) => {
          const Icon = mod.icon;
          return (
            <Card key={mod.title} className="border-border/60 hover:border-border transition-colors cursor-pointer group"
              onClick={() => setLocation(mod.href)}>
              <CardContent className="p-5">
                <div className="flex items-start gap-4">
                  <div className="w-11 h-11 rounded-xl flex items-center justify-center flex-shrink-0" style={{ background: mod.bg }}>
                    <Icon className="w-5 h-5" style={{ color: mod.color }} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <h3 className="font-semibold text-sm">{mod.title}</h3>
                      <ArrowRight className="w-4 h-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                    </div>
                    <p className="text-xs text-muted-foreground mt-1 leading-relaxed">{mod.description}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Test History */}
      {!runSummary && (testHistory?.length ?? 0) > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <FlaskConical className="w-4 h-4 text-purple-400" />
              Recent Test Runs
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {testHistory?.slice(0, 3).map((run) => (
                <div key={run.id} className="flex items-center gap-3 py-2 px-3 rounded-lg text-xs"
                  style={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))" }}>
                  <div className="w-2 h-2 rounded-full" style={{ background: run.summary.fail > 0 ? "#ef4444" : "#22c55e" }} />
                  <span className="flex-1 font-medium">
                    {new Date(run.startedAt).toLocaleString()}
                  </span>
                  <span style={{ color: "#22c55e" }}>{run.summary.pass}P</span>
                  <span style={{ color: "#ef4444" }}>{run.summary.fail}F</span>
                  <span style={{ color: "#facc15" }}>{run.summary.warn}W</span>
                  <span className="text-muted-foreground">{Math.round(run.summary.duration)}ms</span>
                  <button
                    onClick={(e) => { e.stopPropagation(); setViewingRunId(run.runId); setLiveResults(run.results ?? []); setRunSummary(run.summary); setRunStatus("completed"); }}
                    className="text-purple-400 hover:underline"
                  >
                    View
                  </button>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Security Notice */}
      <div className="flex items-start gap-3 rounded-xl px-4 py-3 text-xs"
        style={{ background: "rgba(220,38,38,0.06)", border: "1px solid rgba(220,38,38,0.15)" }}>
        <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" style={{ color: "#f87171" }} />
        <div style={{ color: "rgba(248,113,113,0.85)" }}>
          <span className="font-semibold">Security Notice:</span> All admin actions are logged to the audit trail.
          Ensure you have proper authorisation before making changes to user roles or platform settings.
        </div>
      </div>
    </div>
  );
}
