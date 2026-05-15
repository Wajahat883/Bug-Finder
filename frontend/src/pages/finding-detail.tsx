import { useParams, Link, useLocation } from "wouter";
import {
  useGetFinding,
  useUpdateFinding,
  useCreateRemediation
} from "@/api-client";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ShieldAlert,
  Target,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Wrench,
  Info,
  Github,
  Loader2,
  Zap,
  Code2,
  ExternalLink,
  ArrowLeft,
  Brain,
  Copy,
  Check,
  Link as LinkIcon,
  FileText,
  RefreshCw,
  X,
  Send,
  Shield,
  HelpCircle,
} from "lucide-react";
import { format } from "date-fns";
import { useState, useCallback, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getSlaStatus } from "@/lib/sla";
import { useToast } from "@/hooks/use-toast";
import { MarkdownContent } from "@/lib/markdown";

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-[hsl(var(--critical))] text-white",
    high: "bg-[hsl(var(--high))] text-white",
    medium: "bg-[hsl(var(--medium))] text-black",
    low: "bg-[hsl(var(--low))] text-black",
    info: "bg-[hsl(var(--info))] text-white",
  };
  return (
    <Badge className={`${colors[severity.toLowerCase()] ?? "bg-slate-500 text-white"} border-none uppercase text-xs px-2 py-1`}>
      {severity}
    </Badge>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = useCallback(async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [text]);
  return (
    <button onClick={copy}
      className="inline-flex items-center gap-1 text-xs px-2 py-1 rounded border border-border text-muted-foreground hover:text-foreground hover:border-foreground/30 transition-colors">
      {copied ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
      {copied ? "Copied!" : "Copy"}
    </button>
  );
}

// Shared AI streaming panel with: abort, copy, regenerate, markdown rendering, follow-up multi-turn.
function AiStreamPanel({
  endpoint,
  buttonLabel,
  icon,
  title,
  description,
  emptyText,
  findingContext,
}: {
  endpoint: string;
  buttonLabel: string;
  icon: React.ReactNode;
  title: string;
  description: string;
  emptyText: string;
  findingContext?: { title?: string; category?: string; endpoint?: string };
}) {
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(false);
  const [followUpLoading, setFollowUpLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [followUp, setFollowUp] = useState("");
  const abortRef = useRef<AbortController | null>(null);
  const { toast } = useToast();

  async function generate() {
    setText(""); setDone(false); setLoading(true);
    abortRef.current = new AbortController();
    try {
      const res = await fetch(endpoint, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
        signal: abortRef.current.signal,
      });
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
          } catch { /* ignore parse errors */ }
        }
      }
      setDone(true);
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        setDone(true);
      } else {
        const msg = "Failed to generate AI content. Please try again.";
        setText(msg);
        toast({ title: "AI Error", description: msg, variant: "destructive" });
      }
    } finally {
      setLoading(false);
      abortRef.current = null;
    }
  }

  async function sendFollowUp() {
    if (!followUp.trim() || followUpLoading) return;
    const question = followUp;
    setFollowUp("");
    setFollowUpLoading(true);
    abortRef.current = new AbortController();

    setText(p => p + `\n\n---\n\n**You:** ${question}\n\n**Marcus:**\n`);

    try {
      const systemCtx = findingContext
        ? `You are a senior security engineer. The user is asking a follow-up about: ${findingContext.title ?? "a vulnerability"} (${findingContext.category ?? ""}) at ${findingContext.endpoint ?? ""}. Answer concisely and technically.`
        : "You are a senior security engineer. Answer the follow-up question concisely and technically.";

      const r = await fetch("/api/ai/chat", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: question, system: systemCtx }),
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
    } finally {
      setFollowUpLoading(false);
      abortRef.current = null;
    }
  }

  function abort() {
    abortRef.current?.abort();
  }

  async function copyAll() {
    await navigator.clipboard.writeText(text);
    toast({ title: "Copied to clipboard" });
  }

  const isStreaming = loading || followUpLoading;

  return (
    <Card className="border-violet-500/20">
      <CardHeader className="flex flex-row items-center justify-between pb-3">
        <div>
          <CardTitle className="text-base">{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </div>
        <div className="flex gap-2 flex-shrink-0 flex-wrap justify-end">
          {text && !isStreaming && (
            <>
              <Button size="sm" variant="outline" onClick={copyAll} className="gap-1.5 h-8">
                <Copy className="w-3.5 h-3.5" />Copy
              </Button>
              <Button size="sm" variant="outline" onClick={generate} className="gap-1.5 h-8">
                <RefreshCw className="w-3.5 h-3.5" />Regenerate
              </Button>
            </>
          )}
          {isStreaming && (
            <Button size="sm" variant="outline" onClick={abort}
              className="gap-1.5 h-8 border-red-500/40 text-red-400 hover:bg-red-500/10">
              <X className="w-3.5 h-3.5" />Stop
            </Button>
          )}
          <Button size="sm" onClick={generate} disabled={isStreaming}
            className="bg-violet-600 hover:bg-violet-700 text-white gap-2 h-8">
            {loading ? <><Loader2 className="w-3.5 h-3.5 animate-spin" />Generating…</> : <>{icon}{buttonLabel}</>}
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {!text && !isStreaming && (
          <p className="text-sm text-muted-foreground text-center py-6">{emptyText}</p>
        )}
        {(text || isStreaming) && (
          <div className="prose prose-sm dark:prose-invert max-w-none">
            <MarkdownContent content={text} />
            {isStreaming && <span className="inline-block w-2 h-4 bg-violet-400 animate-pulse ml-1 align-middle" />}
          </div>
        )}
        {done && (
          <div className="mt-4 pt-3 border-t border-border space-y-2">
            <p className="text-xs text-muted-foreground">AI Security Engine · Ask a follow-up below</p>
            <div className="flex gap-2">
              <Input
                placeholder="Ask a follow-up question about this analysis..."
                value={followUp}
                onChange={e => setFollowUp(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendFollowUp(); } }}
                disabled={followUpLoading}
                className="flex-1 h-8 text-sm"
              />
              <Button size="sm" onClick={sendFollowUp} disabled={followUpLoading || !followUp.trim()} className="gap-1.5 h-8">
                {followUpLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
              </Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function RetestButton({ findingId, currentStatus }: { findingId: string; currentStatus?: string }) {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [loading, setLoading] = useState(false);

  async function requestRetest() {
    setLoading(true);
    try {
      const res = await fetch(`/api/findings/${findingId}/retest`, { method: "POST", credentials: "include" });
      if (!res.ok) throw new Error(await res.text());
      qc.invalidateQueries({ queryKey: ["/api/findings", findingId] });
      toast({ title: "Retest requested", description: "The finding has been queued for retesting." });
    } catch (e: unknown) {
      toast({ title: "Retest failed", description: e instanceof Error ? e.message : "Error", variant: "destructive" });
    } finally { setLoading(false); }
  }

  const statusColors: Record<string, string> = {
    pending: "border-yellow-500/40 text-yellow-400",
    running: "border-blue-500/40 text-blue-400",
    passed: "border-green-500/40 text-green-400",
    failed: "border-red-500/40 text-red-400",
  };

  return (
    <div className="flex items-center gap-2">
      {currentStatus && currentStatus !== "none" && (
        <Badge variant="outline" className={`text-[10px] ${statusColors[currentStatus] ?? "border-muted-foreground/40 text-muted-foreground"}`}>
          Retest: {currentStatus}
        </Badge>
      )}
      <Button size="sm" variant="outline" className="text-xs h-7 border-teal-500/40 text-teal-400 hover:bg-teal-500/10 gap-1.5"
        onClick={requestRetest} disabled={loading || currentStatus === "running"}>
        {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
        Retest
      </Button>
    </div>
  );
}

export default function FindingDetail() {
  const params = useParams();
  const [, setLocation] = useLocation();
  const findingId = params.id as string;
  const { toast } = useToast();
  const [ghLoading, setGhLoading] = useState(false);
  const [ghIssueUrl, setGhIssueUrl] = useState<string | null>(null);
  const [ghError, setGhError] = useState<string | null>(null);
  const [jiraLoading, setJiraLoading] = useState(false);
  const [jiraUrl, setJiraUrl] = useState<string | null>(null);

  const qc = useQueryClient();
  const [newComment, setNewComment] = useState("");
  const [triageLoading, setTriageLoading] = useState(false);
  const [fpDialogOpen, setFpDialogOpen] = useState(false);
  const [fpReason, setFpReason] = useState("not_applicable");
  const [fpEvidence, setFpEvidence] = useState("");
  const [aiAssessment, setAiAssessment] = useState<{ fp_probability: number; reasoning: string; cached?: boolean } | null>(null);
  const [aiAssessLoading, setAiAssessLoading] = useState(false);

  async function submitTriage(status: string, extra?: Record<string, unknown>) {
    setTriageLoading(true);
    try {
      const res = await fetch(`/api/findings/${findingId}/triage`, {
        method: "PATCH",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status, ...extra }),
      });
      if (!res.ok) throw new Error(await res.text());
      qc.invalidateQueries({ queryKey: ["/api/findings", findingId] });
      toast({ title: "Triage updated", description: `Status set to ${status.replace(/_/g, " ")}` });
    } catch (e: unknown) {
      toast({ title: "Triage failed", description: e instanceof Error ? e.message : "Unknown error", variant: "destructive" });
    } finally {
      setTriageLoading(false);
    }
  }

  async function runAiAssessment() {
    setAiAssessLoading(true);
    try {
      const res = await fetch(`/api/ai/triage/${findingId}`, { method: "POST", credentials: "include" });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setAiAssessment(data);
    } catch (e: unknown) {
      toast({ title: "AI Assessment failed", description: e instanceof Error ? e.message : "Error", variant: "destructive" });
    } finally {
      setAiAssessLoading(false);
    }
  }

  const { data: comments = [] } = useQuery<any[]>({
    queryKey: ["/api/findings", findingId, "comments"],
    queryFn: () => fetch(`/api/findings/${findingId}/comments`, { credentials: "include" }).then(r => r.json()),
  });

  const addComment = useMutation({
    mutationFn: (text: string) =>
      fetch(`/api/findings/${findingId}/comments`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, author: "You" }),
      }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/findings", findingId, "comments"] });
      setNewComment("");
    },
  });

  const { data: cveData, isLoading: cveLoading, refetch: fetchCve, isFetching: cveFetching } = useQuery({
    queryKey: ["/api/findings", findingId, "cve"],
    queryFn: () => fetch(`/api/findings/${findingId}/cve`, { credentials: "include" }).then(r => r.json()),
    enabled: false,
    staleTime: 300000,
  });

  async function createJiraIssue() {
    setJiraLoading(true);
    try {
      const r = await fetch("/api/integrations/jira/create-issue", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_id: findingId }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error ?? "Failed");
      setJiraUrl(d.url);
      toast({ title: `Jira issue ${d.key} created` });
    } catch (err: unknown) {
      toast({ title: err instanceof Error ? err.message : "Jira error", variant: "destructive" });
    } finally { setJiraLoading(false); }
  }

  async function createGithubIssue() {
    setGhLoading(true); setGhError(null);
    try {
      const r = await fetch("/api/integrations/github/create-issue", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_id: findingId }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error ?? "Failed");
      setGhIssueUrl(d.issue_url);
    } catch (err: unknown) {
      setGhError(err instanceof Error ? err.message : "Failed to create issue");
    } finally { setGhLoading(false); }
  }

  const { data: finding, isLoading } = useGetFinding(findingId, {
    query: { enabled: !!findingId }
  });

  const updateFinding = useUpdateFinding({});

  const createRemediation = useCreateRemediation({
    mutation: {
      onSuccess: () => { setLocation("/remediations"); }
    }
  });

  if (isLoading) {
    return <div className="p-8 flex justify-center text-muted-foreground"><Loader2 className="w-5 h-5 animate-spin mr-2" />Loading finding details...</div>;
  }

  if (!finding) {
    return <div className="p-8 text-center text-destructive">Finding not found</div>;
  }

  const handleUpdateStatus = (status: "real" | "false_positive" | "informational" | "pending") => {
    updateFinding.mutate({ id: finding.id, data: { validation_status: status } });
  };

  const handleCreateRemediation = () => {
    createRemediation.mutate({
      data: {
        finding_id: finding.id,
        title: `Fix: ${finding.title}`,
        description: finding.recommended_fix || "Address the vulnerability described in the finding.",
        patch_snippet: "/* Add patch logic here */\n"
      }
    });
  };

  const cweNum = finding.cwe_id?.replace(/^CWE-/i, "") ?? "";
  const cveId = (finding as Record<string, unknown>).cve_id as string | undefined;
  const findingCtx = {
    title: finding.title,
    category: String((finding as Record<string, unknown>).category ?? ""),
    endpoint: finding.endpoint,
  };

  const tabs = [
    "details", "evidence", "cve", "remediation",
    "payloads", "patch", "patch-gen", "report", "narrative", "poc",
    "tools", "fp", "cvss", "reasoning", "verify",
    "comments",
  ];

  const tabLabels: Record<string, string> = {
    details: "Details",
    evidence: "Evidence",
    cve: "CVE",
    remediation: "Remediation",
    payloads: "Payloads",
    patch: "Patch",
    "patch-gen": "🤖 Auto-Patch",
    report: "BB Report",
    narrative: "Narrative",
    poc: "PoC",
    tools: "Tools",
    fp: "FP Analysis",
    cvss: "CVSS",
    reasoning: "🧠 Reasoning",
    verify: "🔍 Verify",
    comments: "Comments",
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <button onClick={() => history.back()} className="text-muted-foreground hover:text-foreground">
              <ArrowLeft className="w-4 h-4" />
            </button>
            <SeverityBadge severity={finding.severity} />
            <h1 className="text-2xl font-bold tracking-tight">{finding.title}</h1>
          </div>
          <div className="flex flex-wrap items-center gap-4 text-sm text-muted-foreground">
            <span className="flex items-center gap-1.5"><Target className="w-4 h-4" />{finding.target_url}</span>
            <span>Discovered: {format(new Date(finding.created_at), "MMM d, yyyy HH:mm")}</span>
            <Badge variant="secondary" className="text-[10px]">{finding.scanner_name}</Badge>
            {(finding as Record<string, unknown>).category && (
              <Badge variant="outline" className="text-[10px]">{String((finding as Record<string, unknown>).category)}</Badge>
            )}
            {/* EPSS Score Badge */}
            {(finding as Record<string, unknown>).epss_score != null && (() => {
              const epss = Number((finding as Record<string, unknown>).epss_score);
              const color = epss > 0.3 ? "bg-red-500/20 text-red-400 border-red-500/40" : epss > 0.1 ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/40" : "bg-green-500/20 text-green-400 border-green-500/40";
              return (
                <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${color}`} title="EPSS: Exploit Prediction Scoring System">
                  EPSS {(epss * 100).toFixed(1)}%
                </span>
              );
            })()}
            {/* CISA KEV Badge */}
            {(finding as Record<string, unknown>).is_cisa_kev === true && (
              <span className="text-[10px] font-bold px-2 py-0.5 rounded border bg-red-600/20 text-red-300 border-red-600/50" title="CISA Known Exploited Vulnerability">
                ⚠ CISA KEV — Actively Exploited
              </span>
            )}
          </div>
        </div>
        <div className="flex flex-col items-end gap-2 shrink-0">
          <div className="flex gap-2">
            {ghIssueUrl ? (
              <a href={ghIssueUrl} target="_blank" rel="noopener noreferrer">
                <Button variant="outline" size="sm" className="border-green-600 text-green-500">
                  <CheckCircle2 className="w-4 h-4 mr-1.5" /> View GitHub Issue
                </Button>
              </a>
            ) : (
              <Button variant="outline" size="sm" onClick={createGithubIssue} disabled={ghLoading} className="border-gray-600">
                {ghLoading ? <Loader2 className="w-4 h-4 mr-1.5 animate-spin" /> : <Github className="w-4 h-4 mr-1.5" />}
                {ghLoading ? "Creating..." : "GitHub Issue"}
              </Button>
            )}
            {ghError && <span className="text-xs text-red-400">{ghError}</span>}
            {jiraUrl ? (
              <a href={jiraUrl} target="_blank" rel="noopener noreferrer">
                <Button variant="outline" size="sm" className="border-blue-600 text-blue-400">
                  <ExternalLink className="w-4 h-4 mr-1.5" /> View Jira Issue
                </Button>
              </a>
            ) : (
              <Button variant="outline" size="sm" onClick={createJiraIssue} disabled={jiraLoading} className="border-blue-600/40">
                {jiraLoading ? <Loader2 className="w-4 h-4 mr-1.5 animate-spin" /> : <LinkIcon className="w-4 h-4 mr-1.5" />}
                {jiraLoading ? "Creating..." : "Jira Ticket"}
              </Button>
            )}
          </div>
          <div className="flex gap-2 flex-wrap justify-end">
            {(["real", "false_positive", "informational"] as const).map(status => {
              const conf = {
                real: { label: "Valid", icon: <AlertTriangle className="w-4 h-4 mr-1" />, active: "bg-red-500 hover:bg-red-600 text-white" },
                false_positive: { label: "False Positive", icon: <XCircle className="w-4 h-4 mr-1" />, active: "bg-green-500 hover:bg-green-600 text-white" },
                informational: { label: "Info", icon: <Info className="w-4 h-4 mr-1" />, active: "bg-blue-500 hover:bg-blue-600 text-white" },
              }[status];
              return (
                <Button key={status}
                  variant={finding.validation_status === status ? "default" : "outline"} size="sm"
                  className={finding.validation_status === status ? conf.active : ""}
                  onClick={() => handleUpdateStatus(status)}>
                  {conf.icon}{conf.label}
                </Button>
              );
            })}
          </div>
        </div>
      </div>

      {/* ── Phase 1: Triage Bar ─────────────────────────────────────────── */}
      <Card className="border-indigo-500/20 bg-indigo-500/5">
        <CardContent className="p-4">
          <div className="flex flex-wrap items-center gap-3">
            <span className="text-xs font-semibold text-indigo-400 uppercase tracking-wide shrink-0">Triage</span>
            <div className="flex flex-wrap gap-2 flex-1">
              <Button size="sm" variant="outline"
                className="border-green-500/50 text-green-400 hover:bg-green-500/10 gap-1.5"
                disabled={triageLoading}
                onClick={() => submitTriage("confirmed")}>
                <CheckCircle2 className="w-3.5 h-3.5" /> Confirm Real
              </Button>
              <Button size="sm" variant="outline"
                className="border-yellow-500/50 text-yellow-400 hover:bg-yellow-500/10 gap-1.5"
                disabled={triageLoading}
                onClick={() => setFpDialogOpen(true)}>
                <XCircle className="w-3.5 h-3.5" /> Mark False Positive
              </Button>
              <Button size="sm" variant="outline"
                className="border-blue-500/50 text-blue-400 hover:bg-blue-500/10 gap-1.5"
                disabled={triageLoading}
                onClick={() => submitTriage("needs_review")}>
                <HelpCircle className="w-3.5 h-3.5" /> Needs Review
              </Button>
              <Button size="sm" variant="outline"
                className="border-purple-500/50 text-purple-400 hover:bg-purple-500/10 gap-1.5"
                disabled={triageLoading}
                onClick={() => submitTriage("suppressed", { suppressed_until: new Date(Date.now() + 90 * 86400_000).toISOString() })}>
                <Shield className="w-3.5 h-3.5" /> Suppress 90d
              </Button>
              <Button size="sm" variant="outline"
                className="border-violet-500/50 text-violet-400 hover:bg-violet-500/10 gap-1.5"
                disabled={aiAssessLoading}
                onClick={runAiAssessment}>
                {aiAssessLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Brain className="w-3.5 h-3.5" />}
                AI Assess
              </Button>
            </div>
            {triageLoading && <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />}
          </div>

          {/* AI Assessment Result */}
          {aiAssessment && (
            <div className={`mt-3 p-3 rounded-lg border text-sm ${aiAssessment.fp_probability >= 70 ? "bg-green-500/10 border-green-500/30 text-green-300" : aiAssessment.fp_probability >= 40 ? "bg-yellow-500/10 border-yellow-500/30 text-yellow-300" : "bg-red-500/10 border-red-500/30 text-red-300"}`}>
              <div className="flex items-center gap-2 mb-1">
                <Brain className="w-3.5 h-3.5" />
                <span className="font-semibold">AI FP Probability: {aiAssessment.fp_probability}%</span>
                {aiAssessment.cached && <span className="text-xs opacity-60">(cached)</span>}
              </div>
              <p className="text-xs opacity-80">{aiAssessment.reasoning}</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* FP Reason Dialog */}
      {fpDialogOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => setFpDialogOpen(false)}>
          <Card className="w-full max-w-md border-border" onClick={e => e.stopPropagation()}>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <XCircle className="w-4 h-4 text-yellow-400" /> Mark as False Positive
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <label className="text-xs text-muted-foreground block mb-1.5">Reason *</label>
                <select
                  className="w-full bg-background border border-border rounded px-3 py-2 text-sm"
                  value={fpReason}
                  onChange={e => setFpReason(e.target.value)}>
                  <option value="test_environment">Test Environment</option>
                  <option value="accepted_risk">Accepted Risk</option>
                  <option value="compensating_control">Compensating Control</option>
                  <option value="not_applicable">Not Applicable</option>
                  <option value="duplicate">Duplicate Finding</option>
                  <option value="other">Other</option>
                </select>
              </div>
              <div>
                <label className="text-xs text-muted-foreground block mb-1.5">Supporting Evidence</label>
                <textarea
                  className="w-full bg-background border border-border rounded px-3 py-2 text-sm resize-none h-20"
                  placeholder="Describe why this is a false positive..."
                  value={fpEvidence}
                  onChange={e => setFpEvidence(e.target.value)} />
              </div>
              <div className="flex gap-2 justify-end">
                <Button variant="outline" size="sm" onClick={() => setFpDialogOpen(false)}>Cancel</Button>
                <Button size="sm"
                  className="bg-yellow-500 hover:bg-yellow-600 text-black"
                  disabled={triageLoading}
                  onClick={async () => {
                    await submitTriage("false_positive", { fp_reason: fpReason, fp_evidence: fpEvidence });
                    setFpDialogOpen(false);
                  }}>
                  {triageLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" /> : null}
                  Submit for Review
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Suppression Banner */}
      {(finding as Record<string, unknown>).triage_status === "suppressed" && (
        <div className="flex items-center gap-3 px-4 py-3 rounded-lg border border-purple-500/40 bg-purple-500/10 text-purple-300 text-sm">
          <Shield className="w-4 h-4 shrink-0" />
          <span className="flex-1">
            <strong>Suppressed</strong>
            {(finding as Record<string, unknown>).suppressed_until
              ? ` until ${format(new Date(String((finding as Record<string, unknown>).suppressed_until)), "MMM d, yyyy")}`
              : " indefinitely"}
            {!!((finding as Record<string, unknown>).fp_reason) && ` — ${String((finding as Record<string, unknown>).fp_reason).replace(/_/g, " ")}`}
          </span>
          <Button size="sm" variant="outline" className="border-purple-500/50 text-purple-300 text-xs"
            onClick={() => submitTriage("confirmed")}>Unsuppress</Button>
        </div>
      )}

      {/* Compliance Tags + Days Open + Retest */}
      {(() => {
        const tags = (finding as Record<string, unknown>).compliance_tags as string[] | undefined;
        const daysOpen = (finding as Record<string, unknown>).days_open as number | null | undefined;
        const retestStatus = (finding as Record<string, unknown>).retest_status as string | undefined;
        return (
          <div className="flex flex-wrap items-center gap-3">
            {tags && tags.length > 0 && (
              <div className="flex flex-wrap gap-1.5 items-center">
                <span className="text-xs text-muted-foreground">Compliance:</span>
                {tags.map(tag => (
                  <Badge key={tag} variant="outline" className="text-[10px] border-cyan-500/40 text-cyan-400">{tag}</Badge>
                ))}
              </div>
            )}
            {daysOpen != null && (
              <Badge variant="outline" className={`text-[10px] ${daysOpen > 30 ? "border-red-500/40 text-red-400" : daysOpen > 14 ? "border-yellow-500/40 text-yellow-400" : "border-muted-foreground/40 text-muted-foreground"}`}>
                Open {daysOpen}d
              </Badge>
            )}
            <RetestButton findingId={findingId} currentStatus={retestStatus} />
          </div>
        );
      })()}

      {/* KPI Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground font-medium">CVSS Score</CardTitle></CardHeader>
          <CardContent>
            <div className={`text-3xl font-bold font-mono ${(finding.cvss_score ?? 0) >= 9 ? "text-red-500" : (finding.cvss_score ?? 0) >= 7 ? "text-orange-500" : (finding.cvss_score ?? 0) >= 4 ? "text-yellow-500" : "text-blue-400"}`}>
              {finding.cvss_score ? finding.cvss_score.toFixed(1) : "N/A"}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground font-medium">CWE ID</CardTitle></CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <div className="text-2xl font-bold font-mono text-muted-foreground">{finding.cwe_id || "N/A"}</div>
              {cweNum && (
                <a href={`https://cwe.mitre.org/data/definitions/${cweNum}.html`} target="_blank" rel="noopener noreferrer"
                  className="text-muted-foreground hover:text-foreground"><ExternalLink className="w-3.5 h-3.5" /></a>
              )}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground font-medium">SLA Deadline</CardTitle></CardHeader>
          <CardContent>
            {(() => {
              const sev = finding.severity.toLowerCase();
              if (sev === "info") return <div className="text-lg font-bold font-mono text-muted-foreground">N/A</div>;
              const sla = getSlaStatus(sev, finding.created_at);
              return (
                <div>
                  <div className={`text-2xl font-bold font-mono ${sla.color}`}>{sla.label}</div>
                  {sla.deadline && <div className="text-[10px] text-muted-foreground mt-0.5">{format(sla.deadline, "MMM d, HH:mm")}</div>}
                </div>
              );
            })()}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm text-muted-foreground font-medium">Endpoint</CardTitle></CardHeader>
          <CardContent>
            <div className="text-xs font-mono truncate bg-muted/50 p-2 rounded border border-border">
              {finding.endpoint}
            </div>
            {cveId && (
              <div className="mt-2 flex items-center gap-1.5 text-xs">
                <Badge variant="outline" className="text-xs border-orange-500/40 text-orange-400">{cveId}</Badge>
                <a href={`https://nvd.nist.gov/vuln/detail/${cveId}`} target="_blank" rel="noopener noreferrer"
                  className="text-muted-foreground hover:text-orange-400"><ExternalLink className="w-3 h-3" /></a>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="details" className="w-full">
        <TabsList className="w-full justify-start border-b border-border rounded-none bg-transparent h-auto p-0 flex-wrap">
          {tabs.map(tab => (
            <TabsTrigger key={tab} value={tab}
              className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent px-4 py-3 text-xs">
              {tabLabels[tab] ?? tab}
            </TabsTrigger>
          ))}
        </TabsList>

        {/* Details */}
        <TabsContent value="details" className="pt-6 space-y-4">
          <Card>
            <CardHeader><CardTitle>Vulnerability Details</CardTitle></CardHeader>
            <CardContent>
              <div className="prose prose-sm dark:prose-invert max-w-none">
                {finding.description.split("\n\n").map((p, i) => <p key={i}>{p}</p>)}
              </div>
            </CardContent>
          </Card>
          {(finding as Record<string, unknown>).references && Array.isArray((finding as Record<string, unknown>).references) && (
            <Card>
              <CardHeader><CardTitle className="text-base">References</CardTitle></CardHeader>
              <CardContent>
                <ul className="space-y-1">
                  {((finding as Record<string, unknown>).references as string[]).map((ref, i) => (
                    <li key={i}>
                      <a href={ref} target="_blank" rel="noopener noreferrer"
                        className="text-sm text-primary hover:underline flex items-center gap-1.5">
                        <ExternalLink className="w-3 h-3 shrink-0" />{ref}
                      </a>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Evidence */}
        <TabsContent value="evidence" className="pt-6">
          <Card>
            <CardHeader className="flex flex-row items-start justify-between">
              <div>
                <CardTitle>Proof of Concept / Evidence</CardTitle>
                <CardDescription>Raw HTTP requests, responses, or scanner output</CardDescription>
              </div>
              {finding.evidence && <CopyButton text={finding.evidence} />}
            </CardHeader>
            <CardContent>
              {finding.evidence ? (
                <pre className="p-4 bg-black/40 text-foreground font-mono text-xs overflow-x-auto rounded-md border border-border whitespace-pre-wrap break-all">
                  {finding.evidence}
                </pre>
              ) : (
                <div className="text-center py-12 text-muted-foreground">No specific evidence payload recorded.</div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* CVE Enrichment */}
        <TabsContent value="cve" className="pt-6">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle>CVE / NVD Enrichment</CardTitle>
                <CardDescription>Related CVEs from the NIST National Vulnerability Database</CardDescription>
              </div>
              <Button size="sm" variant="outline" onClick={() => fetchCve()} disabled={cveFetching}>
                {cveFetching ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Fetching…</> : <>Fetch CVEs</>}
              </Button>
            </CardHeader>
            <CardContent>
              {!cveData ? (
                <div className="py-12 text-center text-muted-foreground text-sm">
                  Click "Fetch CVEs" to query the NVD for CVEs related to{" "}
                  <span className="font-mono">{finding.cwe_id || "this vulnerability type"}</span>.
                </div>
              ) : cveData.error ? (
                <div className="py-8 text-center text-red-400 text-sm">{cveData.error}</div>
              ) : !cveData.cves?.length ? (
                <div className="py-8 text-center text-muted-foreground text-sm">No CVEs found for this vulnerability type.</div>
              ) : (
                <div className="space-y-3">
                  <p className="text-xs text-muted-foreground">{cveData.cves.length} CVE(s) found · Source: NVD API 2.0</p>
                  {cveData.cves.map((cve: any) => (
                    <div key={cve.id} className="border border-border rounded-lg p-4">
                      <div className="flex items-start justify-between gap-3 mb-2">
                        <div className="flex items-center gap-2 flex-wrap">
                          <Badge variant="outline" className="text-orange-400 border-orange-500/30 font-mono text-xs">{cve.id}</Badge>
                          {cve.cvssScore && (
                            <Badge variant="outline" className={`text-xs font-mono ${cve.cvssScore >= 9 ? "text-red-400 border-red-500/30" : cve.cvssScore >= 7 ? "text-orange-400 border-orange-500/30" : "text-yellow-400 border-yellow-500/30"}`}>
                              CVSS {cve.cvssScore}
                            </Badge>
                          )}
                          {cve.published && (
                            <span className="text-xs text-muted-foreground">{format(new Date(cve.published), "MMM yyyy")}</span>
                          )}
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <CopyButton text={cve.id} />
                          <a href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" rel="noopener noreferrer"
                            className="text-muted-foreground hover:text-foreground">
                            <ExternalLink className="w-3.5 h-3.5" />
                          </a>
                        </div>
                      </div>
                      {cve.description && (
                        <p className="text-sm text-muted-foreground line-clamp-3">{cve.description}</p>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Remediation */}
        <TabsContent value="remediation" className="pt-6 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Recommended Fix</CardTitle>
              <CardDescription>Guidance on how to resolve this vulnerability</CardDescription>
            </CardHeader>
            <CardContent>
              {finding.recommended_fix ? (
                <div className="prose prose-sm dark:prose-invert max-w-none mb-6">
                  {finding.recommended_fix.split("\n\n").map((p, i) => <p key={i}>{p}</p>)}
                </div>
              ) : (
                <div className="text-center py-6 text-muted-foreground mb-6">No specific remediation guidance provided.</div>
              )}
              <div className="border-t border-border pt-6 flex justify-between items-center">
                <div>
                  <h4 className="text-sm font-medium mb-1">Create Remediation Task</h4>
                  <p className="text-xs text-muted-foreground">Track the resolution of this vulnerability.</p>
                </div>
                <Button onClick={handleCreateRemediation} disabled={createRemediation.isPending}>
                  <Wrench className="w-4 h-4 mr-2" />
                  {createRemediation.isPending ? "Creating..." : "Track Remediation"}
                </Button>
              </div>
            </CardContent>
          </Card>

          <AiStreamPanel
            endpoint={`/api/ai/finding-advice/${findingId}`}
            buttonLabel="Get AI Advice"
            icon={<Wrench className="w-4 h-4" />}
            title="AI Remediation Advice"
            description="Step-by-step fix guidance with root cause analysis and prevention measures"
            emptyText={`Click "Get AI Advice" for specific, developer-friendly fix instructions.`}
            findingContext={findingCtx}
          />
        </TabsContent>

        {/* Attack Payloads */}
        <TabsContent value="payloads" className="pt-6">
          <AiStreamPanel
            endpoint={`/api/ai/payloads/${findingId}`}
            buttonLabel="Generate Payloads"
            icon={<Zap className="w-4 h-4" />}
            title="AI Attack Payload Generator"
            description="Category-specific attack payloads with injection points, bypass techniques, and detection tips"
            emptyText={`Click "Generate Payloads" to create targeted attack payloads. For authorized testing only.`}
            findingContext={findingCtx}
          />
        </TabsContent>

        {/* Code Patch */}
        <TabsContent value="patch" className="pt-6">
          <AiStreamPanel
            endpoint={`/api/ai/patch-diff/${findingId}`}
            buttonLabel="Generate Patch"
            icon={<Code2 className="w-4 h-4" />}
            title="Code Patch Diff"
            description="Unified diff showing vulnerable vs fixed code with deployment checklist"
            emptyText="Click to generate a ready-to-apply code patch for this vulnerability."
            findingContext={findingCtx}
          />
        </TabsContent>

        {/* Bug Bounty Report */}
        <TabsContent value="report" className="pt-6">
          <AiStreamPanel
            endpoint={`/api/ai/bug-bounty-report/${findingId}`}
            buttonLabel="Generate Report"
            icon={<FileText className="w-4 h-4" />}
            title="Bug Bounty Report"
            description="Complete HackerOne/Bugcrowd-formatted submission report"
            emptyText="Click to generate a professional bug bounty report optimized for triage acceptance."
            findingContext={findingCtx}
          />
        </TabsContent>

        {/* Attack Narrative */}
        <TabsContent value="narrative" className="pt-6">
          <AiStreamPanel
            endpoint={`/api/ai/attack-narrative/${findingId}`}
            buttonLabel="Generate Narrative"
            icon={<Zap className="w-4 h-4" />}
            title="Attack Narrative"
            description="Hacker-perspective attack story with MITRE ATT&CK TTPs for security awareness training"
            emptyText="Click to generate a realistic attack narrative from the threat actor's perspective."
            findingContext={findingCtx}
          />
        </TabsContent>

        {/* PoC */}
        <TabsContent value="poc" className="pt-6">
          <AiStreamPanel
            endpoint={`/api/ai/poc/${findingId}`}
            buttonLabel="Generate PoC"
            icon={<Code2 className="w-4 h-4" />}
            title="Proof of Concept"
            description="Complete PoC with HTTP request, curl command, Python script, and detection artifacts"
            emptyText="Click to generate a proof-of-concept with exact HTTP requests and a minimal automation script."
            findingContext={findingCtx}
          />
        </TabsContent>

        {/* Tool Recommendations */}
        <TabsContent value="tools" className="pt-6">
          <AiStreamPanel
            endpoint={`/api/ai/tools/${findingId}`}
            buttonLabel="Get Tool Recommendations"
            icon={<Shield className="w-4 h-4" />}
            title="Security Tool Recommendations"
            description="Burp extensions, nuclei templates, CLI commands, and OSINT techniques for this vulnerability type"
            emptyText="Click to get specific tool recommendations — Burp plugins, nuclei template IDs, and exact CLI commands to find and confirm this vulnerability."
            findingContext={findingCtx}
          />
        </TabsContent>

        {/* False Positive Analysis */}
        <TabsContent value="fp" className="pt-6">
          <AiStreamPanel
            endpoint={`/api/ai/false-positive/${findingId}`}
            buttonLabel="Analyze Finding"
            icon={<HelpCircle className="w-4 h-4" />}
            title="False Positive Analysis"
            description="AI assessment of whether this finding is real or a false positive, with confidence score and verification steps"
            emptyText="Click to get an AI verdict on whether this finding is a real vulnerability or a false positive."
            findingContext={findingCtx}
          />
        </TabsContent>

        {/* CVSS Breakdown */}
        <TabsContent value="cvss" className="pt-6">
          <AiStreamPanel
            endpoint={`/api/ai/cvss-breakdown/${findingId}`}
            buttonLabel="Explain CVSS Score"
            icon={<Info className="w-4 h-4" />}
            title="CVSS Score Breakdown"
            description="Plain-English explanation of each CVSS metric and how to reduce the score through mitigations"
            emptyText="Click to get a plain-English breakdown of the CVSS score and actionable ways to reduce it."
            findingContext={findingCtx}
          />
        </TabsContent>

        {/* 🤖 Auto-Patch Generator */}
        <TabsContent value="patch-gen" className="pt-6">
          <AiStreamPanel
            endpoint={`/api/ai/generate-patch/${findingId}`}
            buttonLabel="Generate Production Patch"
            icon={<Code2 className="w-4 h-4" />}
            title="🤖 AI Auto-Patch Generator"
            description="Complete production patch with vulnerable code, fixed code, unified diff, security tests, and deployment checklist"
            emptyText={`Click to generate a production-ready code patch. AI detects your tech stack and generates language-specific fixes with tests.`}
            findingContext={findingCtx}
          />
        </TabsContent>

        {/* 🧠 AI Reasoning Chain */}
        <TabsContent value="reasoning" className="pt-6">
          <AiStreamPanel
            endpoint={`/api/ai/reasoning-chain/${findingId}`}
            buttonLabel="Show Reasoning Chain"
            icon={<Brain className="w-4 h-4" />}
            title="🧠 AI Explainable Reasoning Chain"
            description="Step-by-step chain of thought: discovery → confirmation → exploitation → impact → root cause. Includes MITRE ATT&CK TTPs, similar CVEs, and prevention patterns."
            emptyText={`Click to see the AI's complete reasoning chain — how it discovered this vulnerability, confirmed it's real, and what the root cause is.`}
            findingContext={findingCtx}
          />
        </TabsContent>

        {/* 🔍 Safe Exploit Verification */}
        <TabsContent value="verify" className="pt-6">
          <AiStreamPanel
            endpoint={`/api/ai/verify-finding/${findingId}`}
            buttonLabel="Verify Finding"
            icon={<Shield className="w-4 h-4" />}
            title="🔍 Safe Exploit Verification"
            description="AI generates a SAFE, non-destructive proof-of-concept to confirm this is a real vulnerability — never modifies or deletes data, never executes harmful commands."
            emptyText={`Click to verify this finding with a safe exploit. AI generates only non-destructive tests (SLEEP for SQLi, document.domain for XSS, etc.).`}
            findingContext={findingCtx}
          />
        </TabsContent>

        {/* Comments */}
        <TabsContent value="comments" className="pt-6">
          <div className="space-y-3">
            <div className="flex gap-2">
              <textarea
                value={newComment}
                onChange={e => setNewComment(e.target.value)}
                placeholder="Add a comment..."
                className="flex-1 rounded-md border border-input bg-background px-3 py-2 text-sm resize-none h-20"
              />
              <Button onClick={() => newComment.trim() && addComment.mutate(newComment)} disabled={!newComment.trim()}>Post</Button>
            </div>
            {comments.length === 0 ? (
              <p className="text-sm text-muted-foreground">No comments yet.</p>
            ) : comments.map((c: any) => (
              <div key={c.id} className="p-3 rounded-lg border border-border bg-muted/20">
                <div className="flex items-center gap-2 mb-1 text-xs text-muted-foreground">
                  <span className="font-medium text-foreground">{c.author}</span>
                  <span>{new Date(c.created_at).toLocaleString()}</span>
                </div>
                <p className="text-sm">{c.text}</p>
              </div>
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
