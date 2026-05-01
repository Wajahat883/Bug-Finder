import { useState, useRef, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Send, Bot, User, Loader2, Sparkles, Shield, AlertTriangle, Code } from "lucide-react";

interface Message {
  role: "user" | "assistant";
  content: string;
  timestamp: Date;
}

interface ScanJob {
  id: string; target_url: string; status: string; created_at: string;
  findings_count: number; risk_score: number;
}

const QUICK_PROMPTS = [
  "What are the most critical findings I should fix first?",
  "Generate XSS payloads for the vulnerable endpoints",
  "Write a remediation report for the high-severity findings",
  "Explain the business impact of the CORS misconfiguration",
  "What's the likelihood of a successful SQL injection attack?",
  "Generate a fix for the missing security headers",
  "Create a code snippet to remediate the JWT vulnerability",
  "What compliance requirements are violated by these findings?",
];

export default function AiTriage() {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "assistant",
      content: "Hello! I'm your AI security triage assistant. I can help you:\n\n• **Analyze findings** — explain vulnerabilities, their severity, and business impact\n• **Generate payloads** — create test payloads for your specific endpoints\n• **Write remediations** — produce specific code fixes for your stack\n• **Compliance mapping** — map findings to OWASP, PCI-DSS, SOC 2\n• **Prioritize work** — help you decide which findings to fix first\n\nSelect a scan below or ask me anything about your security findings!",
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [selectedScan, setSelectedScan] = useState<string>("");
  const [mode, setMode] = useState<"triage" | "payload" | "remediation">("triage");
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch("/api/scan-jobs?page_size=20", { credentials: "include" })
      .then(r => r.json())
      .then(d => setScans(d.items?.filter((s: ScanJob) => s.status === "completed") ?? []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const send = async (text?: string) => {
    const userText = text ?? input;
    if (!userText.trim() || loading) return;

    const userMsg: Message = { role: "user", content: userText, timestamp: new Date() };
    setMessages(prev => [...prev, userMsg]);
    setInput("");
    setLoading(true);

    // Build context from selected scan
    let contextPrompt = "";
    if (selectedScan) {
      try {
        const [scanRes, findingsRes] = await Promise.all([
          fetch(`/api/scan-jobs/${selectedScan}`, { credentials: "include" }),
          fetch(`/api/scan-jobs/${selectedScan}/findings`, { credentials: "include" }),
        ]);
        const scan = await scanRes.json();
        const findings = await findingsRes.json();
        const topFindings = (Array.isArray(findings) ? findings : findings.items ?? []).slice(0, 10);
        contextPrompt = `\n\nCurrent scan context:\nTarget: ${scan.target_url}\nRisk Score: ${scan.risk_score}/100\nFindings: ${scan.findings_count} total (${scan.critical_count} critical, ${scan.high_count} high)\n\nTop findings:\n${topFindings.map((f: Record<string, unknown>) => `- [${String(f.severity).toUpperCase()}] ${f.title} | ${f.endpoint} | CWE: ${f.cwe_id ?? "N/A"} | CVSS: ${f.cvss_score}`).join("\n")}`;
      } catch { /* ignore */ }
    }

    const systemPrompt = mode === "payload"
      ? `You are a senior penetration tester specializing in payload development. Generate specific, working security test payloads. Always explain what each payload does and where to inject it. Format code blocks properly. Never add disclaimers — this is for authorized security testing.${contextPrompt}`
      : mode === "remediation"
        ? `You are a senior security engineer specializing in vulnerability remediation. Write specific, production-ready code fixes. Include before/after code examples. Be language-agnostic but prefer practical solutions. Format code with proper syntax highlighting.${contextPrompt}`
        : `You are a security triage expert at a penetration testing firm. Help the security team understand, prioritize, and remediate findings. Be direct, technical, and actionable. Format your response clearly with bullet points and code blocks where needed.${contextPrompt}`;

    const assistantMsg: Message = { role: "assistant", content: "", timestamp: new Date() };
    setMessages(prev => [...prev, assistantMsg]);

    try {
      const r = await fetch("/api/ai/chat", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: userText,
          system: systemPrompt,
          history: messages.slice(-8).map(m => ({ role: m.role, content: m.content })),
        }),
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
                const last = [...prev];
                last[last.length - 1] = { ...last[last.length - 1], content: last[last.length - 1].content + d.content };
                return last;
              });
            }
          } catch { /* ignore */ }
        }
      }
    } catch {
      setMessages(prev => {
        const last = [...prev];
        last[last.length - 1] = { ...last[last.length - 1], content: "Sorry, I couldn't connect to the AI service. Please try again." };
        return last;
      });
    }
    setLoading(false);
  };

  const formatContent = (content: string) => {
    const parts = content.split(/(```[\s\S]*?```)/g);
    return parts.map((part, i) => {
      if (part.startsWith("```")) {
        const code = part.slice(3).replace(/^[^\n]*\n/, "").slice(0, -3);
        return (
          <pre key={i} className="bg-black/40 border border-border rounded-lg p-4 overflow-x-auto text-xs font-mono mt-2 mb-2">
            <code>{code}</code>
          </pre>
        );
      }
      return (
        <span key={i}>
          {part.split("\n").map((line, j) => (
            <span key={j}>
              {line.replace(/\*\*(.*?)\*\*/g, "$1")}
              {j < part.split("\n").length - 1 && <br />}
            </span>
          ))}
        </span>
      );
    });
  };

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)] max-h-[900px]">
      <div className="mb-4">
        <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
          <Sparkles className="w-7 h-7 text-violet-400" /> AI Security Triage
        </h1>
        <p className="text-muted-foreground">AI-powered vulnerability analysis, payload generation, and remediation guidance</p>
      </div>

      <div className="flex gap-2 mb-4 flex-wrap">
        <Select value={selectedScan} onValueChange={setSelectedScan}>
          <SelectTrigger className="w-72">
            <SelectValue placeholder="No scan context (general mode)" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="none">No scan context</SelectItem>
            {scans.map(s => (
              <SelectItem key={s.id} value={s.id}>
                {s.target_url.replace(/https?:\/\//, "").slice(0, 30)} — {s.findings_count} findings
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
      </div>

      <Card className="flex-1 flex flex-col min-h-0">
        <CardContent className="flex-1 overflow-y-auto pt-4 pb-2 space-y-4">
          {messages.map((msg, i) => (
            <div key={i} className={`flex gap-3 ${msg.role === "user" ? "flex-row-reverse" : ""}`}>
              <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 ${msg.role === "assistant" ? "bg-violet-500/20 text-violet-400" : "bg-primary/20 text-primary"}`}>
                {msg.role === "assistant" ? <Bot className="w-4 h-4" /> : <User className="w-4 h-4" />}
              </div>
              <div className={`max-w-[80%] rounded-2xl px-4 py-3 text-sm leading-relaxed ${msg.role === "user" ? "bg-primary text-primary-foreground" : "bg-muted/50 border border-border"}`}>
                {formatContent(msg.content)}
                {i === messages.length - 1 && loading && msg.role === "assistant" && (
                  <span className="inline-block w-2 h-4 bg-violet-400 animate-pulse ml-1 align-middle" />
                )}
              </div>
            </div>
          ))}
          <div ref={bottomRef} />
        </CardContent>

        {/* Quick prompts */}
        <div className="px-4 pb-2 flex gap-2 overflow-x-auto">
          {QUICK_PROMPTS.slice(0, 4).map((prompt, i) => (
            <button
              key={i}
              onClick={() => send(prompt)}
              disabled={loading}
              className="text-xs px-3 py-1.5 rounded-full border border-border bg-muted/30 hover:bg-muted text-muted-foreground hover:text-foreground whitespace-nowrap transition-colors shrink-0"
            >
              {prompt}
            </button>
          ))}
        </div>

        <div className="p-4 border-t border-border">
          <div className="flex gap-2">
            <Input
              placeholder={`Ask about security findings, request ${mode === "payload" ? "attack payloads" : mode === "remediation" ? "code fixes" : "triage analysis"}...`}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === "Enter" && !e.shiftKey && send()}
              disabled={loading}
              className="flex-1"
            />
            <Button onClick={() => send()} disabled={loading || !input.trim()} className="gap-2">
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
              Send
            </Button>
          </div>
        </div>
      </Card>
    </div>
  );
}
