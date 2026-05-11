import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { format } from "date-fns";
import {
  Github, Slack, Link, Plug, Plus, Trash2, Play, Pause,
  Mail, Calendar, Send, CheckCircle2, XCircle, AlertTriangle, Globe,
} from "lucide-react";

// ── helpers ───────────────────────────────────────────────────────────────

function StatusBadge({ connected }: { connected: boolean }) {
  return connected ? (
    <Badge className="bg-green-500/15 text-green-500 border-green-500/30 gap-1">
      <CheckCircle2 className="w-3 h-3" /> Connected
    </Badge>
  ) : (
    <Badge variant="outline" className="text-muted-foreground gap-1">
      <XCircle className="w-3 h-3" /> Not configured
    </Badge>
  );
}

// ── Jira config panel ─────────────────────────────────────────────────────

function JiraPanel({ jira }: { jira: any }) {
  const { toast } = useToast();
  const [open, setOpen] = useState(false);

  return (
    <Card>
      <CardContent className="p-5">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg flex items-center justify-center bg-blue-500/15">
              <Link className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <div className="font-semibold">Jira</div>
              <div className="text-xs text-muted-foreground">Create issues from findings</div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <StatusBadge connected={jira?.connected} />
            <Button variant="outline" size="sm" onClick={() => setOpen((v) => !v)}>
              Configure
            </Button>
          </div>
        </div>

        {open && (
          <div className="mt-4 pt-4 border-t border-border space-y-3 text-sm">
            <p className="text-muted-foreground text-xs">
              Set these environment variables on the API server (restart required):
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {[
                { key: "JIRA_URL", label: "Jira Base URL", hint: "https://yourorg.atlassian.net", val: jira?.url },
                { key: "JIRA_EMAIL", label: "Account Email", hint: "you@company.com", val: jira?.email },
                { key: "JIRA_API_TOKEN", label: "API Token", hint: "Generate at id.atlassian.com", val: "" },
                { key: "JIRA_PROJECT_KEY", label: "Project Key", hint: "e.g. SEC", val: jira?.projectKey },
              ].map((f) => (
                <div key={f.key}>
                  <Label className="text-xs mb-1">{f.label}</Label>
                  <Input
                    readOnly
                    value={f.val || ""}
                    placeholder={f.hint}
                    className="font-mono text-xs h-8"
                  />
                  <p className="text-[10px] text-muted-foreground mt-0.5">Env: <code>{f.key}</code></p>
                </div>
              ))}
            </div>
            <p className="text-[11px] text-muted-foreground">
              Once configured, a "Create Jira Ticket" button will appear on each finding detail page.
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ── Report Schedules panel ─────────────────────────────────────────────────

interface Schedule {
  id: string;
  name: string;
  recipients: string[];
  cron_expression: string;
  target_url?: string;
  enabled: boolean;
  last_sent?: string;
}

function ReportSchedulesPanel() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [recipients, setRecipients] = useState("");
  const [cron, setCron] = useState("0 8 * * 1");
  const [targetUrl, setTargetUrl] = useState("");

  const { data: schedules = [] } = useQuery<Schedule[]>({
    queryKey: ["/api/report-schedules"],
    queryFn: () => fetch("/api/report-schedules", { credentials: "include" }).then((r) => r.json()),
  });

  const create = useMutation({
    mutationFn: (body: object) =>
      fetch("/api/report-schedules", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/report-schedules"] });
      setShowForm(false); setName(""); setRecipients(""); setCron("0 8 * * 1"); setTargetUrl("");
      toast({ title: "Report schedule created" });
    },
    onError: () => toast({ title: "Failed to create schedule", variant: "destructive" }),
  });

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      fetch(`/api/report-schedules/${id}`, {
        method: "PATCH", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled }),
      }).then((r) => r.json()),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["/api/report-schedules"] }),
  });

  const remove = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/report-schedules/${id}`, { method: "DELETE", credentials: "include" }).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/report-schedules"] });
      toast({ title: "Schedule deleted" });
    },
  });

  const sendNow = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/report-schedules/${id}/send-now`, { method: "POST", credentials: "include" }).then((r) => r.json()),
    onSuccess: (d) => toast({ title: d.ok ? "Report sent!" : d.message ?? "SMTP not configured" }),
  });

  function handleCreate() {
    if (!name || !recipients) return;
    create.mutate({
      name, recipients: recipients.split(",").map((s) => s.trim()).filter(Boolean),
      cron_expression: cron, target_url: targetUrl || undefined,
    });
  }

  const CRON_PRESETS = [
    { label: "Weekly (Mon 8am)", value: "0 8 * * 1" },
    { label: "Daily (8am)", value: "0 8 * * *" },
    { label: "Monthly (1st)", value: "0 8 1 * *" },
  ];

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base flex items-center gap-2">
            <Mail className="w-5 h-5 text-primary" />
            Scheduled Email Reports
          </CardTitle>
          <Button size="sm" variant="outline" onClick={() => setShowForm((v) => !v)}>
            <Plus className="w-4 h-4 mr-1.5" />New Schedule
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">
          Automatically email HTML security reports to stakeholders on a schedule.
        </p>
      </CardHeader>
      <CardContent className="space-y-3">
        {/* Create form */}
        {showForm && (
          <div className="rounded-lg border border-primary/30 bg-primary/5 p-4 space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <Label className="text-xs mb-1">Report Name</Label>
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Weekly Security Summary" className="h-8 text-sm" />
              </div>
              <div>
                <Label className="text-xs mb-1">Target URL (optional)</Label>
                <Input value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)} placeholder="https://example.com" className="h-8 text-sm" />
              </div>
              <div className="sm:col-span-2">
                <Label className="text-xs mb-1">Recipients (comma-separated emails)</Label>
                <Input value={recipients} onChange={(e) => setRecipients(e.target.value)} placeholder="ciso@company.com, dev@company.com" className="h-8 text-sm" />
              </div>
              <div>
                <Label className="text-xs mb-1">Cron Expression</Label>
                <Input value={cron} onChange={(e) => setCron(e.target.value)} placeholder="0 8 * * 1" className="h-8 text-sm font-mono" />
              </div>
              <div>
                <Label className="text-xs mb-1">Presets</Label>
                <div className="flex gap-1.5 flex-wrap">
                  {CRON_PRESETS.map((p) => (
                    <button key={p.value} onClick={() => setCron(p.value)}
                      className="text-[10px] px-2 py-1 rounded border border-border hover:border-primary/40 transition-colors">
                      {p.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="ghost" size="sm" onClick={() => setShowForm(false)}>Cancel</Button>
              <Button size="sm" onClick={handleCreate} disabled={create.isPending}>
                <Calendar className="w-4 h-4 mr-1.5" />Create Schedule
              </Button>
            </div>
          </div>
        )}

        {/* List */}
        {schedules.length === 0 && !showForm ? (
          <div className="py-8 text-center text-muted-foreground text-sm">
            No report schedules yet. Create one to start emailing stakeholders automatically.
          </div>
        ) : (
          schedules.map((s) => (
            <div key={s.id} className="flex items-start gap-3 p-3 rounded-lg border border-border hover:bg-accent/20 transition-colors">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="font-medium text-sm">{s.name}</span>
                  <Badge variant={s.enabled ? "default" : "outline"} className="text-[10px] px-1.5 py-0">
                    {s.enabled ? "Active" : "Paused"}
                  </Badge>
                </div>
                <p className="text-xs text-muted-foreground">
                  <code className="font-mono">{s.cron_expression}</code>
                  {s.target_url && <> · {s.target_url}</>}
                </p>
                <p className="text-xs text-muted-foreground mt-0.5">
                  To: {s.recipients.join(", ")}
                  {s.last_sent && <> · Last sent {format(new Date(s.last_sent), "MMM d, HH:mm")}</>}
                </p>
              </div>
              <div className="flex items-center gap-1.5 flex-shrink-0">
                <Button variant="ghost" size="icon" className="h-7 w-7"
                  title="Send now"
                  onClick={() => sendNow.mutate(s.id)}>
                  <Send className="w-3.5 h-3.5" />
                </Button>
                <Button variant="ghost" size="icon" className="h-7 w-7"
                  title={s.enabled ? "Pause" : "Resume"}
                  onClick={() => toggle.mutate({ id: s.id, enabled: !s.enabled })}>
                  {s.enabled ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                </Button>
                <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive"
                  title="Delete"
                  onClick={() => remove.mutate(s.id)}>
                  <Trash2 className="w-3.5 h-3.5" />
                </Button>
              </div>
            </div>
          ))
        )}
      </CardContent>
    </Card>
  );
}

// ── Webhook Manager panel ─────────────────────────────────────────────────

interface Webhook {
  id: string;
  name: string;
  url: string;
  events: string[];
  enabled: boolean;
  last_triggered?: string;
  last_status?: number;
}

const WEBHOOK_EVENTS = ["finding.created", "scan.completed", "scan.failed", "remediation.updated", "sla.breach"];

function WebhookManagerPanel() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [events, setEvents] = useState<string[]>(["finding.created"]);

  const { data: webhooks = [] } = useQuery<Webhook[]>({
    queryKey: ["/api/webhooks"],
    queryFn: () => fetch("/api/webhooks", { credentials: "include" }).then(r => r.json()),
  });

  const create = useMutation({
    mutationFn: (body: object) =>
      fetch("/api/webhooks", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/webhooks"] });
      setShowForm(false); setName(""); setUrl(""); setEvents(["finding.created"]);
      toast({ title: "Webhook created" });
    },
    onError: () => toast({ title: "Failed to create webhook", variant: "destructive" }),
  });

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      fetch(`/api/webhooks/${id}`, {
        method: "PATCH", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled }),
      }).then(r => r.json()),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["/api/webhooks"] }),
  });

  const remove = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/webhooks/${id}`, { method: "DELETE", credentials: "include" }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/webhooks"] });
      toast({ title: "Webhook deleted" });
    },
  });

  const testHook = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/webhooks/${id}/test`, { method: "POST", credentials: "include" }).then(r => r.json()),
    onSuccess: (d) => toast({ title: d.ok ? "Test delivery sent" : d.message ?? "Test failed" }),
  });

  function toggleEvent(ev: string) {
    setEvents(p => p.includes(ev) ? p.filter(e => e !== ev) : [...p, ev]);
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base flex items-center gap-2">
            <Plug className="w-5 h-5 text-primary" />
            Webhook Endpoints
          </CardTitle>
          <Button size="sm" variant="outline" onClick={() => setShowForm(v => !v)}>
            <Plus className="w-4 h-4 mr-1.5" />New Webhook
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">Receive HTTP POST callbacks for platform events.</p>
      </CardHeader>
      <CardContent className="space-y-3">
        {showForm && (
          <div className="rounded-lg border border-primary/30 bg-primary/5 p-4 space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <Label className="text-xs mb-1">Name</Label>
                <Input value={name} onChange={e => setName(e.target.value)} placeholder="Slack alerts" className="h-8 text-sm" />
              </div>
              <div>
                <Label className="text-xs mb-1">URL</Label>
                <Input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://hooks.example.com/..." className="h-8 text-sm" />
              </div>
            </div>
            <div>
              <Label className="text-xs mb-2 block">Events</Label>
              <div className="flex flex-wrap gap-1.5">
                {WEBHOOK_EVENTS.map(ev => (
                  <button key={ev} onClick={() => toggleEvent(ev)}
                    className={`text-[11px] px-2 py-1 rounded border transition-colors font-mono ${events.includes(ev) ? "border-primary/60 bg-primary/10 text-primary" : "border-border text-muted-foreground"}`}>
                    {ev}
                  </button>
                ))}
              </div>
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="ghost" size="sm" onClick={() => setShowForm(false)}>Cancel</Button>
              <Button size="sm" onClick={() => create.mutate({ name, url, events })} disabled={create.isPending || !name || !url || !events.length}>
                Create Webhook
              </Button>
            </div>
          </div>
        )}
        {webhooks.length === 0 && !showForm ? (
          <div className="py-8 text-center text-muted-foreground text-sm">No webhooks configured yet.</div>
        ) : (
          webhooks.map(w => (
            <div key={w.id} className="flex items-start gap-3 p-3 rounded-lg border border-border hover:bg-accent/20 transition-colors">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="font-medium text-sm">{w.name}</span>
                  <Badge variant={w.enabled ? "default" : "outline"} className="text-[10px] px-1.5 py-0">
                    {w.enabled ? "Active" : "Paused"}
                  </Badge>
                  {w.last_status && (
                    <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${w.last_status >= 200 && w.last_status < 300 ? "text-green-500 border-green-500/30" : "text-red-500 border-red-500/30"}`}>
                      {w.last_status}
                    </Badge>
                  )}
                </div>
                <p className="text-xs text-muted-foreground font-mono truncate">{w.url}</p>
                <p className="text-xs text-muted-foreground mt-0.5">{w.events.join(", ")}</p>
              </div>
              <div className="flex items-center gap-1.5 flex-shrink-0">
                <Button variant="ghost" size="icon" className="h-7 w-7" title="Send test" onClick={() => testHook.mutate(w.id)}>
                  <Send className="w-3.5 h-3.5" />
                </Button>
                <Button variant="ghost" size="icon" className="h-7 w-7" title={w.enabled ? "Pause" : "Resume"}
                  onClick={() => toggle.mutate({ id: w.id, enabled: !w.enabled })}>
                  {w.enabled ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                </Button>
                <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive"
                  onClick={() => remove.mutate(w.id)}>
                  <Trash2 className="w-3.5 h-3.5" />
                </Button>
              </div>
            </div>
          ))
        )}
      </CardContent>
    </Card>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────

export default function Integrations() {
  const { toast } = useToast();

  const { data } = useQuery<Record<string, any>>({
    queryKey: ["/api/integrations"],
    queryFn: () => fetch("/api/integrations", { credentials: "include" }).then((r) => r.json()),
  });

  function testSlack() {
    fetch("/api/integrations/slack/test", { method: "POST", credentials: "include" })
      .then((r) => r.json())
      .then((d) => toast({ title: d.ok ? "Slack test message sent!" : d.error ?? "Failed" }));
  }

  const integrations = [
    {
      key: "github",
      name: "GitHub",
      desc: "Create issues from findings automatically",
      icon: <Github className="w-5 h-5 text-foreground" />,
      color: "#24292e",
      envVars: ["GITHUB_TOKEN"],
      action: null,
    },
    {
      key: "slack",
      name: "Slack",
      desc: "Real-time alerts for critical findings & SLA breaches",
      icon: <Slack className="w-5 h-5 text-[#4a154b]" />,
      color: "#4a154b",
      envVars: ["SLACK_WEBHOOK_URL"],
      action: data?.["slack"]?.connected
        ? { label: "Send Test", fn: testSlack }
        : null,
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
          <Plug className="w-7 h-7" />
          Integrations
        </h1>
        <p className="text-muted-foreground mt-1">
          Connect external tools and automate security workflows.
        </p>
      </div>

      {/* Standard integrations */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {integrations.map((intg) => (
          <Card key={intg.key}>
            <CardContent className="p-5">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-lg flex items-center justify-center border border-border bg-muted/40">
                    {intg.icon}
                  </div>
                  <div>
                    <div className="font-semibold">{intg.name}</div>
                    <div className="text-xs text-muted-foreground">{intg.desc}</div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <StatusBadge connected={data?.[intg.key]?.connected ?? false} />
                  {intg.action && (
                    <Button variant="outline" size="sm" onClick={intg.action.fn}>
                      {intg.action.label}
                    </Button>
                  )}
                </div>
              </div>
              {!data?.[intg.key]?.connected && (
                <p className="text-xs text-muted-foreground mt-3">
                  Set <code className="font-mono">{intg.envVars.join(", ")}</code> environment variable to enable.
                </p>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Jira */}
      <JiraPanel jira={data?.["jira"]} />

      {/* Scheduled email reports */}
      <ReportSchedulesPanel />

      {/* Webhooks */}
      <WebhookManagerPanel />

      {/* Status note */}
      {!process.env["NODE_ENV"] && (
        <div className="flex items-start gap-2 p-3 rounded-lg border border-yellow-500/30 bg-yellow-500/10 text-sm text-yellow-600">
          <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
          <span>SMTP must be configured (SMTP_HOST, SMTP_USER, SMTP_PASS) for email reports to be delivered.</span>
        </div>
      )}
    </div>
  );
}
