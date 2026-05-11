import { useParams, Link, useLocation } from "wouter";
import {
  useGetFinding,
  useUpdateFinding,
  useCreateRemediation
} from "@workspace/api-client-react";
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
    "payloads", "patch", "report", "narrative", "poc",
    "tools", "fp", "cvss",
    "comments",
  ];

  const tabLabels: Record<string, string> = {
    details: "Details",
    evidence: "Evidence",
    cve: "CVE",
    remediation: "Remediation",
    payloads: "Payloads",
    patch: "Patch",
    report: "BB Report",
    narrative: "Narrative",
    poc: "PoC",
    tools: "Tools",
    fp: "FP Analysis",
    cvss: "CVSS",
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
