import { useState, useRef, useEffect } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Send, Bot, User, Loader2, Sparkles, Shield, AlertTriangle, Code, X, Copy, Check } from "lucide-react";
import { MarkdownContent } from "@/lib/markdown";
import { useToast } from "@/hooks/use-toast";

interface Message {
  role: "user" | "assistant";
  content: string;
  timestamp: Date;
}

interface ScanJob {
  id: string;
  target_url: string;
  status: string;
  created_at: string;
  findings_count: number;
  risk_score: number;
  critical_count?: number;
  high_count?: number;
}

interface FindingSummary {
  title: string;
  severity: string;
  endpoint: string;
  category: string;
  cwe_id?: string;
  cvss_score?: number;
}

// Build context-aware quick prompts from real scan data.
function buildDynamicPrompts(scan: ScanJob, findings: FindingSummary[]): string[] {
  const prompts: string[] = [];
  const cats = findings.map(f => (f.category ?? "").toLowerCase());

  // Category-specific prompts with real endpoint data
  const xss = findings.find(f => cats[findings.indexOf(f)]?.includes("xss"));
  if (xss) prompts.push(`Generate XSS payloads for ${xss.endpoint.slice(0, 50)}`);

  const sqli = findings.find(f => cats[findings.indexOf(f)]?.includes("sql"));
  if (sqli) prompts.push(`Show SQLi exploitation steps for ${sqli.endpoint.slice(0, 50)}`);

  const ssrf = findings.find(f => cats[findings.indexOf(f)]?.includes("ssrf"));
  if (ssrf) prompts.push(`Generate SSRF payloads to exfiltrate cloud metadata from ${ssrf.endpoint.slice(0, 50)}`);

  const idor = findings.find(f => cats[findings.indexOf(f)]?.includes("idor") || cats[findings.indexOf(f)]?.includes("access"));
  if (idor) prompts.push(`How do I confirm and escalate the IDOR at ${idor.endpoint.slice(0, 50)}?`);

  // Generic high-value prompts with real counts
  if ((scan.critical_count ?? 0) > 0) {
    prompts.push(`What is the fastest exploitation path through the ${scan.critical_count} critical findings on ${scan.target_url.replace(/https?:\/\//, "")}?`);
  }

  prompts.push(`Prioritize the ${scan.findings_count} findings on ${scan.target_url.replace(/https?:\/\//, "")} for a 1-week sprint`);
  prompts.push(`Which findings on ${scan.target_url.replace(/https?:\/\//, "")} violate PCI-DSS or GDPR?`);
  prompts.push(`Write a 3-sentence executive summary of the risk score ${scan.risk_score}/100 for ${scan.target_url.replace(/https?:\/\//, "")}`);

  return prompts.slice(0, 4);
}

const FALLBACK_PROMPTS = [
  "What are the most critical findings I should fix first?",
  "Generate XSS payloads for the vulnerable endpoints",
  "Write a remediation report for the high-severity findings",
  "What compliance requirements are violated by these findings?",
];

export default function AiTriage() {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "assistant",
      content: "Hello! I'm **Marcus**, your AI security engineer. I can help you:\n\n- **Analyze findings** — explain vulnerabilities, severity, and business impact\n- **Generate payloads** — create test payloads for your specific endpoints\n- **Write remediations** — produce specific code fixes for your stack\n- **Compliance mapping** — map findings to OWASP, PCI-DSS, SOC 2, GDPR\n- **Prioritize work** — help you decide what to fix first and how long it will take\n\nSelect a scan below for context-aware analysis, or ask me anything about security.",
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [selectedScan, setSelectedScan] = useState<string>("");
  const [selectedScanData, setSelectedScanData] = useState<ScanJob | null>(null);
  const [scanFindings, setScanFindings] = useState<FindingSummary[]>([]);
  const [mode, setMode] = useState<"triage" | "payload" | "remediation">("triage");
  const [quickPrompts, setQuickPrompts] = useState<string[]>(FALLBACK_PROMPTS);
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const abortRef = useRef<AbortController | null>(null);
  const { toast } = useToast();

  useEffect(() => {
    fetch("/api/scan-jobs?page_size=20", { credentials: "include" })
      .then(r => r.json())
      .then(d => setScans(d.items?.filter((s: ScanJob) => s.status === "completed") ?? []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // When scan is selected, fetch its data and build dynamic quick prompts.
  useEffect(() => {
    if (!selectedScan || selectedScan === "none") {
      setSelectedScanData(null);
      setScanFindings([]);
      setQuickPrompts(FALLBACK_PROMPTS);
      return;
    }

    Promise.all([
      fetch(`/api/scan-jobs/${selectedScan}`, { credentials: "include" }).then(r => r.json()),
      fetch(`/api/scan-jobs/${selectedScan}/findings`, { credentials: "include" }).then(r => r.json()),
    ]).then(([scan, findingsData]) => {
      const findings: FindingSummary[] = (Array.isArray(findingsData) ? findingsData : findingsData.items ?? []).slice(0, 15);
      setSelectedScanData(scan);
      setScanFindings(findings);
      setQuickPrompts(buildDynamicPrompts(scan, findings));
    }).catch(() => {
      setQuickPrompts(FALLBACK_PROMPTS);
    });
  }, [selectedScan]);

  function stopStreaming() {
    abortRef.current?.abort();
    setLoading(false);
  }

  async function send(text?: string) {
    const userText = text ?? input;
    if (!userText.trim() || loading) return;

    const userMsg: Message = { role: "user", content: userText, timestamp: new Date() };
    setMessages(prev => [...prev, userMsg]);
    setInput("");
    setLoading(true);

    // Build scan context string from cached data
    let contextPrompt = "";
    if (selectedScan && selectedScanData) {
      const topFindings = scanFindings.slice(0, 10);
      contextPrompt = `\n\n## Scan Context\nTarget: ${selectedScanData.target_url}\nRisk Score: ${selectedScanData.risk_score}/100\nFindings: ${selectedScanData.findings_count} total (${selectedScanData.critical_count ?? 0} critical, ${selectedScanData.high_count ?? 0} high)\n\nTop Findings:\n${topFindings.map(f => `- [${f.severity.toUpperCase()}] ${f.title} | ${f.endpoint} | CWE: ${f.cwe_id ?? "N/A"} | CVSS: ${f.cvss_score ?? "N/A"}`).join("\n")}`;
    }

    const systemPrompt = mode === "payload"
      ? `You are Marcus, a senior penetration tester specializing in payload development. Generate specific, working security test payloads with injection points and expected responses. Format code blocks properly. This is for authorized security testing.${contextPrompt}`
      : mode === "remediation"
        ? `You are Marcus, a senior security engineer. Write specific, production-ready code fixes with before/after examples. Be language-agnostic but practical. Use proper syntax highlighting.${contextPrompt}`
        : `You are Marcus, a senior offensive security engineer. Help security teams understand, prioritize, and remediate findings. Be direct, technical, and actionable. Use CVSS scores, CWE IDs, and MITRE ATT&CK TTPs where relevant.${contextPrompt}`;

    const assistantMsg: Message = { role: "assistant", content: "", timestamp: new Date() };
    setMessages(prev => [...prev, assistantMsg]);

    abortRef.current = new AbortController();

    try {
      const r = await fetch("/api/ai/chat", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: userText,
          system: systemPrompt,
          history: messages.slice(-10).map(m => ({ role: m.role, content: m.content })),
        }),
        signal: abortRef.current.signal,
      });

      if (!r.ok) throw new Error("AI chat failed");
      const reader = r.body!.getReader();
      const decoder = new TextDecoder();
      let buf = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try {
            const d = JSON.parse(line.slice(6));
            if (d.content) {
              setMessages(prev => {
                const updated = [...prev];
                updated[updated.length - 1] = {
                  ...updated[updated.length - 1],
                  content: updated[updated.length - 1].content + d.content,
                };
                return updated;
              });
            }
          } catch { /* */ }
        }
      }
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        // Stream was stopped by user — message is already partially populated, that's fine
      } else {
        setMessages(prev => {
          const updated = [...prev];
          updated[updated.length - 1] = {
            ...updated[updated.length - 1],
            content: updated[updated.length - 1].content || "Sorry, I couldn't connect to the AI service. Please try again.",
          };
          return updated;
        });
      }
    } finally {
      setLoading(false);
      abortRef.current = null;
    }
  }

  async function copyMessage(content: string, idx: number) {
    await navigator.clipboard.writeText(content);
    setCopiedIdx(idx);
    setTimeout(() => setCopiedIdx(null), 2000);
  }

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)] max-h-[900px]">
      <div className="mb-4">
        <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
          <Sparkles className="w-7 h-7 text-violet-400" /> AI Security Triage
        </h1>
        <p className="text-muted-foreground">Context-aware vulnerability analysis, payload generation, and remediation guidance</p>
      </div>

      {/* Controls */}
      <div className="flex gap-2 mb-4 flex-wrap items-center">
        <Select value={selectedScan} onValueChange={setSelectedScan}>
          <SelectTrigger className="w-80">
            <SelectValue placeholder="No scan context (general mode)" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="none">No scan context — general mode</SelectItem>
            {scans.map(s => (
              <SelectItem key={s.id} value={s.id}>
                {s.target_url.replace(/https?:\/\//, "").slice(0, 35)} — {s.findings_count} findings · Risk {s.risk_score}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <div className="flex rounded-lg border border-border overflow-hidden">
          {[
            { value: "triage", label: "Triage", icon: <Shield className="w-3.5 h-3.5" /> },
            { value: "payload", label: "Payloads", icon: <AlertTriangle className="w-3.5 h-3.5" /> },
            { value: "remediation", label: "Remediation", icon: <Code className="w-3.5 h-3.5" /> },
          ].map(({ value, label, icon }) => (
            <button
              key={value}
              onClick={() => setMode(value as typeof mode)}
              className={`flex items-center gap-1.5 px-3 py-2 text-sm transition-colors ${mode === value ? "bg-primary text-primary-foreground" : "hover:bg-muted"}`}
            >
              {icon} {label}
            </button>
          ))}
        </div>

        {selectedScanData && (
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <div className="w-2 h-2 rounded-full bg-green-400" />
            Context: {selectedScanData.target_url.replace(/https?:\/\//, "").slice(0, 30)} · {selectedScanData.findings_count} findings
          </div>
        )}
      </div>

      <Card className="flex-1 flex flex-col min-h-0">
        {/* Messages */}
        <CardContent className="flex-1 overflow-y-auto pt-4 pb-2 space-y-4">
          {messages.map((msg, i) => (
            <div key={i} className={`flex gap-3 ${msg.role === "user" ? "flex-row-reverse" : ""}`}>
              <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 ${msg.role === "assistant" ? "bg-violet-500/20 text-violet-400" : "bg-primary/20 text-primary"}`}>
                {msg.role === "assistant" ? <Bot className="w-4 h-4" /> : <User className="w-4 h-4" />}
              </div>
              <div className={`max-w-[80%] rounded-2xl px-4 py-3 text-sm leading-relaxed relative group ${msg.role === "user" ? "bg-primary text-primary-foreground" : "bg-muted/50 border border-border"}`}>
                {msg.role === "assistant" ? (
                  <MarkdownContent content={msg.content} />
                ) : (
                  <span>{msg.content}</span>
                )}
                {i === messages.length - 1 && loading && msg.role === "assistant" && (
                  <span className="inline-block w-2 h-4 bg-violet-400 animate-pulse ml-1 align-middle" />
                )}
                {/* Copy button on assistant messages */}
                {msg.role === "assistant" && msg.content && (
                  <button
                    onClick={() => copyMessage(msg.content, i)}
                    className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity p-1 rounded border border-border bg-background text-muted-foreground hover:text-foreground"
                    title="Copy message"
                  >
                    {copiedIdx === i ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
                  </button>
                )}
              </div>
            </div>
          ))}
          <div ref={bottomRef} />
        </CardContent>

        {/* Dynamic quick prompts */}
        <div className="px-4 pb-2 flex gap-2 overflow-x-auto">
          {quickPrompts.map((prompt, i) => (
            <button
              key={`${selectedScan}-${i}`}
              onClick={() => send(prompt)}
              disabled={loading}
              className="text-xs px-3 py-1.5 rounded-full border border-border bg-muted/30 hover:bg-muted text-muted-foreground hover:text-foreground whitespace-nowrap transition-colors shrink-0"
              title={prompt}
            >
              {prompt.length > 45 ? prompt.slice(0, 45) + "…" : prompt}
            </button>
          ))}
        </div>

        {/* Input */}
        <div className="p-4 border-t border-border">
          <div className="flex gap-2">
            <Input
              placeholder={
                mode === "payload" ? "Ask for specific payloads or bypass techniques…" :
                mode === "remediation" ? "Ask for code fixes, patches, or secure configuration…" :
                "Ask about vulnerabilities, risk prioritization, or compliance impact…"
              }
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === "Enter" && !e.shiftKey && send()}
              disabled={loading}
              className="flex-1"
            />
            {loading ? (
              <Button onClick={stopStreaming} variant="outline" className="gap-2 border-red-500/40 text-red-400 hover:bg-red-500/10 shrink-0">
                <X className="w-4 h-4" />Stop
              </Button>
            ) : (
              <Button onClick={() => send()} disabled={!input.trim()} className="gap-2 shrink-0">
                <Send className="w-4 h-4" />Send
              </Button>
            )}
          </div>
        </div>
      </Card>
    </div>
  );
}
