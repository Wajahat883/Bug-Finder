import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { format } from "date-fns";
import {
  Github, Slack, Link, Plug, Plus, Trash2, Play, Pause,
  Mail, Calendar, Send, CheckCircle2, XCircle, AlertTriangle, Globe,
  Activity, Clock, BarChart2, RefreshCw, List,
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

// ── Webhook Delivery Log ──────────────────────────────────────────────────

interface WebhookDelivery {
  id: string;
  webhook_id: string;
  event: string;
  status_code: number | null;
  duration_ms: number | null;
  success: boolean;
  created_at: string;
}

function WebhookDeliveryLogDialog({ webhookId, webhookName, open, onClose }: {
  webhookId: string;
  webhookName: string;
  open: boolean;
  onClose: () => void;
}) {
  const { toast } = useToast();

  const { data: deliveries = [], isLoading, refetch } = useQuery<WebhookDelivery[]>({
    queryKey: ["/api/integrations/webhooks", webhookId, "deliveries"],
    queryFn: () =>
      fetch(`/api/integrations/webhooks/${webhookId}/deliveries`, { credentials: "include" }).then(r => r.json()),
    enabled: open,
    refetchInterval: open ? 30000 : false,
  });

  // Restart auto-refresh interval when dialog opens
  useEffect(() => {
    if (open) refetch();
  }, [open, refetch]);

  const retryDelivery = useMutation({
    mutationFn: (deliveryId: string) =>
      fetch(`/api/integrations/webhooks/${webhookId}/deliveries/${deliveryId}/retry`, {
        method: "POST",
        credentials: "include",
      }).then(r => r.json()),
    onSuccess: () => {
      refetch();
      toast({ title: "Delivery retried" });
    },
    onError: () => toast({ title: "Retry failed", variant: "destructive" }),
  });

  return (
    <Dialog open={open} onOpenChange={v => { if (!v) onClose(); }}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <List className="w-4 h-4 text-primary" />
            Delivery Log — {webhookName}
          </DialogTitle>
        </DialogHeader>

        {isLoading ? (
          <div className="flex justify-center py-10">
            <RefreshCw className="w-5 h-5 animate-spin text-muted-foreground" />
          </div>
        ) : deliveries.length === 0 ? (
          <div className="py-10 text-center text-sm text-muted-foreground">
            No deliveries recorded yet for this webhook.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-xs text-muted-foreground">
                  <th className="text-left px-3 py-2 font-medium">Time</th>
                  <th className="text-left px-3 py-2 font-medium">Event</th>
                  <th className="text-right px-3 py-2 font-medium">Status</th>
                  <th className="text-right px-3 py-2 font-medium">Duration</th>
                  <th className="text-center px-3 py-2 font-medium">Result</th>
                  <th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {deliveries.map(d => (
                  <tr key={d.id} className="hover:bg-accent/20 transition-colors">
                    <td className="px-3 py-2 text-xs text-muted-foreground whitespace-nowrap">
                      {format(new Date(d.created_at), "MMM d, HH:mm:ss")}
                    </td>
                    <td className="px-3 py-2">
                      <code className="text-[11px] font-mono text-primary/80">{d.event}</code>
                    </td>
                    <td className="px-3 py-2 text-right font-mono text-xs">
                      {d.status_code != null ? (
                        <span className={d.status_code >= 200 && d.status_code < 300 ? "text-green-400" : "text-red-400"}>
                          {d.status_code}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-right text-xs text-muted-foreground">
                      {d.duration_ms != null ? `${d.duration_ms}ms` : "—"}
                    </td>
                    <td className="px-3 py-2 text-center">
                      {d.success ? (
                        <Badge className="text-[10px] bg-green-500/15 text-green-500 border-green-500/30 gap-1">
                          <CheckCircle2 className="w-3 h-3" /> OK
                        </Badge>
                      ) : (
                        <Badge className="text-[10px] bg-red-500/15 text-red-400 border-red-500/30 gap-1">
                          <XCircle className="w-3 h-3" /> Failed
                        </Badge>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      {!d.success && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-6 text-xs"
                          onClick={() => retryDelivery.mutate(d.id)}
                          disabled={retryDelivery.isPending}
                        >
                          <RefreshCw className="w-3 h-3 mr-1" /> Retry
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <p className="text-[11px] text-muted-foreground text-right mt-1">Auto-refreshes every 30s while open.</p>
      </DialogContent>
    </Dialog>
  );
}

function WebhookManagerPanel() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [events, setEvents] = useState<string[]>(["finding.created"]);
  const [deliveryLogWebhook, setDeliveryLogWebhook] = useState<{ id: string; name: string } | null>(null);

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
                <Button variant="ghost" size="sm" className="h-7 text-xs gap-1" title="View delivery log"
                  onClick={() => setDeliveryLogWebhook({ id: w.id, name: w.name })}>
                  <List className="w-3.5 h-3.5" /> Deliveries
                </Button>
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

      {deliveryLogWebhook && (
        <WebhookDeliveryLogDialog
          webhookId={deliveryLogWebhook.id}
          webhookName={deliveryLogWebhook.name}
          open={!!deliveryLogWebhook}
          onClose={() => setDeliveryLogWebhook(null)}
        />
      )}
    </Card>
  );
}

// ── Integration Health Dashboard ──────────────────────────────────────────

interface WebhookHealth {
  id: string;
  name: string;
  url: string;
  enabled: boolean;
  delivery_count: number;
  last_triggered: string | null;
  last_status: number | null;
  last_ok: boolean | null;
  status: "healthy" | "failing" | "untested";
}

interface HealthData {
  webhooks: WebhookHealth[];
  summary: { total: number; healthy: number; failing: number; untested: number };
}

function WebhookHealthPanel() {
  const { data, isLoading } = useQuery<HealthData>({
    queryKey: ["/api/integrations/health"],
    queryFn: () => fetch("/api/integrations/health", { credentials: "include" }).then(r => r.json()),
    refetchInterval: 30000,
  });

  const statusColors: Record<string, string> = {
    healthy: "text-green-500 border-green-500/30 bg-green-500/10",
    failing: "text-red-500 border-red-500/30 bg-red-500/10",
    untested: "text-muted-foreground border-border bg-muted/20",
  };

  if (isLoading) return null;
  if (!data || data.webhooks.length === 0) return null;

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base flex items-center gap-2">
            <Activity className="w-5 h-5 text-primary" />
            Webhook Delivery Health
          </CardTitle>
          <div className="flex items-center gap-3 text-xs text-muted-foreground">
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-green-500 inline-block" />{data.summary.healthy} healthy</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500 inline-block" />{data.summary.failing} failing</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-muted-foreground/40 inline-block" />{data.summary.untested} untested</span>
          </div>
        </div>
        <p className="text-xs text-muted-foreground">Real-time delivery status for all enabled webhooks.</p>
      </CardHeader>
      <CardContent className="space-y-2">
        {data.webhooks.map(hook => (
          <div key={hook.id} className="flex items-center gap-3 p-3 rounded-lg border border-border hover:bg-accent/20 transition-colors">
            <Badge className={`text-[10px] px-1.5 py-0 border capitalize shrink-0 ${statusColors[hook.status]}`}>
              {hook.status}
            </Badge>
            <div className="flex-1 min-w-0">
              <div className="font-medium text-sm truncate">{String(hook.name)}</div>
              <div className="text-[11px] text-muted-foreground font-mono truncate">{hook.url}</div>
            </div>
            <div className="flex items-center gap-3 shrink-0 text-xs text-muted-foreground">
              <span className="flex items-center gap-1" title="Delivery count">
                <BarChart2 className="w-3.5 h-3.5" />
                {hook.delivery_count}
              </span>
              {hook.last_triggered && (
                <span className="flex items-center gap-1" title="Last triggered">
                  <Clock className="w-3.5 h-3.5" />
                  {format(new Date(hook.last_triggered), "MMM d, HH:mm")}
                </span>
              )}
              {hook.last_status != null && (
                <Badge variant="outline" className={`text-[10px] px-1.5 py-0 font-mono ${hook.last_ok ? "text-green-500 border-green-500/30" : "text-red-400 border-red-500/30"}`}>
                  {hook.last_status}
                </Badge>
              )}
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

// ── OAuth Integrations ────────────────────────────────────────────────────

const OAUTH_INTEGRATIONS = [
  { id: "jira", name: "Jira", icon: "🎫", description: "Create and sync Jira tickets from findings", connectUrl: "/api/integrations/oauth/jira/begin" },
  { id: "github", name: "GitHub", icon: "🐙", description: "Create GitHub issues from findings", connectUrl: "/api/integrations/oauth/github/begin" },
  { id: "slack", name: "Slack", icon: "💬", description: "Send alerts to Slack channels", connectUrl: "/api/integrations/oauth/slack/begin" },
  { id: "pagerduty", name: "PagerDuty", icon: "🚨", description: "Trigger PagerDuty incidents for critical findings", connectUrl: "/api/integrations/oauth/pagerduty/begin" },
  { id: "linear", name: "Linear", icon: "📐", description: "Create Linear issues from findings", connectUrl: "/api/integrations/oauth/linear/begin" },
];

interface OAuthConnection {
  id: string;
  integration_id: string;
  account_name: string;
  permissions: string[];
  connected_at: string;
  last_sync: string | null;
}

function OAuthIntegrationsPanel() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [confirmDisconnect, setConfirmDisconnect] = useState<string | null>(null);

  const { data: connections = [] } = useQuery<OAuthConnection[]>({
    queryKey: ["/api/integrations/connections"],
    queryFn: () => fetch("/api/integrations/connections", { credentials: "include" }).then(r => r.json()),
  });

  const disconnect = useMutation({
    mutationFn: (connectionId: string) =>
      fetch(`/api/integrations/connections/${connectionId}`, { method: "DELETE", credentials: "include" }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/integrations/connections"] });
      toast({ title: "Integration disconnected" });
      setConfirmDisconnect(null);
    },
    onError: () => toast({ title: "Failed to disconnect", variant: "destructive" }),
  });

  const testConnection = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/integrations/${id}/test`, { method: "POST", credentials: "include" }).then(r => r.json()),
    onSuccess: (d) => toast({ title: d.ok ? d.message : "Test failed", variant: d.ok ? "default" : "destructive" }),
    onError: () => toast({ title: "Test failed", variant: "destructive" }),
  });

  const syncNow = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/integrations/${id}/sync`, { method: "POST", credentials: "include" }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/integrations/connections"] });
      toast({ title: "Sync initiated" });
    },
    onError: () => toast({ title: "Sync failed", variant: "destructive" }),
  });

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <Globe className="w-5 h-5 text-primary" />
          Connected Integrations
        </CardTitle>
        <p className="text-xs text-muted-foreground">Connect third-party services via OAuth for seamless workflow integration.</p>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {OAUTH_INTEGRATIONS.map(intg => {
            const conn = connections.find(c => c.integration_id === intg.id);
            return (
              <div key={intg.id} className="rounded-lg border border-border p-4 flex flex-col gap-3">
                <div className="flex items-start gap-3">
                  <span className="text-2xl leading-none mt-0.5">{intg.icon}</span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-semibold text-sm">{intg.name}</span>
                      {conn ? (
                        <Badge className="bg-green-500/15 text-green-500 border-green-500/30 gap-1 text-[10px]">
                          <CheckCircle2 className="w-3 h-3" /> Connected
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="text-muted-foreground text-[10px]">
                          <XCircle className="w-3 h-3 mr-1" /> Not Connected
                        </Badge>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground mt-0.5">{intg.description}</p>
                  </div>
                </div>

                {conn ? (
                  <div className="space-y-2">
                    <div className="text-xs text-muted-foreground space-y-0.5">
                      <p><span className="font-medium">Account:</span> {conn.account_name}</p>
                      <p><span className="font-medium">Connected:</span> {format(new Date(conn.connected_at), "MMM d, yyyy")}</p>
                      {conn.last_sync && (
                        <p><span className="font-medium">Last sync:</span> {format(new Date(conn.last_sync), "MMM d, HH:mm")}</p>
                      )}
                      {conn.permissions.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-1">
                          {conn.permissions.map(p => (
                            <Badge key={p} variant="outline" className="text-[9px] px-1.5 py-0 font-mono">{p}</Badge>
                          ))}
                        </div>
                      )}
                    </div>
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <Button size="sm" variant="outline" className="h-7 text-xs"
                        onClick={() => testConnection.mutate(intg.id)}
                        disabled={testConnection.isPending}>
                        Test Connection
                      </Button>
                      <Button size="sm" variant="outline" className="h-7 text-xs"
                        onClick={() => syncNow.mutate(intg.id)}
                        disabled={syncNow.isPending}>
                        Sync Now
                      </Button>
                      {confirmDisconnect === conn.id ? (
                        <>
                          <Button size="sm" variant="destructive" className="h-7 text-xs"
                            onClick={() => disconnect.mutate(conn.id)}
                            disabled={disconnect.isPending}>
                            Confirm
                          </Button>
                          <Button size="sm" variant="ghost" className="h-7 text-xs"
                            onClick={() => setConfirmDisconnect(null)}>
                            Cancel
                          </Button>
                        </>
                      ) : (
                        <Button size="sm" variant="ghost" className="h-7 text-xs text-destructive hover:text-destructive"
                          onClick={() => setConfirmDisconnect(conn.id)}>
                          Disconnect
                        </Button>
                      )}
                    </div>
                  </div>
                ) : (
                  <Button size="sm" variant="outline" className="self-start"
                    onClick={() => { window.location.href = intg.connectUrl; }}>
                    Connect {intg.name}
                  </Button>
                )}
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────

export default function Integrations() {
  const { toast } = useToast();

  const { data, isError } = useQuery<Record<string, any>>({
    queryKey: ["/api/integrations"],
    queryFn: () => fetch("/api/integrations", { credentials: "include" }).then((r) => r.json()),
  });

  if (isError) return (
    <div className="flex flex-col items-center justify-center h-64 gap-4">
      <AlertTriangle className="w-12 h-12 text-red-400" />
      <p className="text-muted-foreground text-sm">Failed to load data. Please try again.</p>
      <Button variant="outline" size="sm" onClick={() => window.location.reload()}>Retry</Button>
    </div>
  );

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

      {/* OAuth Integrations */}
      <OAuthIntegrationsPanel />

      {/* Scheduled email reports */}
      <ReportSchedulesPanel />

      {/* Webhooks */}
      <WebhookManagerPanel />

      {/* Webhook delivery health */}
      <WebhookHealthPanel />

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
