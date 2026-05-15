import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useGetSettings, useUpdateSettings } from "@/api-client";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Save, Key, Webhook, Bell, BrainCircuit, Activity, Mail, RefreshCw, Eye, EyeOff, ShieldCheck, QrCode, Smartphone, Send, Loader2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

const AI_MODELS = [
  { value: "nemotron-3-super-free", label: "Nemotron 3 Super (Default)" },
  { value: "nemotron-70b-instruct", label: "Nemotron 70B Instruct" },
  { value: "llama-3.1-70b-instruct", label: "Llama 3.1 70B" },
  { value: "llama-3.1-405b-instruct", label: "Llama 3.1 405B" },
  { value: "mistral-large", label: "Mistral Large" },
  { value: "qwen2.5-72b-instruct", label: "Qwen 2.5 72B" },
];

export default function Settings() {
  const { toast } = useToast();
  const { data: settings, isLoading } = useGetSettings();
  const [showApiKey, setShowApiKey] = useState(false);
  const [apiKey, setApiKey] = useState("");
  const [regenerating, setRegenerating] = useState(false);

  const [smtpTesting, setSmtpTesting] = useState(false);
  const [formData, setFormData] = useState({
    default_export_format: "json",
    webhook_url: "",
    slack_webhook_url: "",
    teams_webhook_url: "",
    pagerduty_routing_key: "",
    notifications_enabled: false,
    ai_analysis_enabled: true,
    max_concurrent_scans: 3,
    ai_model: "nemotron-3-super-free",
    smtp_host: "",
    smtp_port: 587,
    smtp_user: "",
    smtp_from: "noreply@bugfinder.io",
  });

  useEffect(() => {
    if (settings) {
      const s = settings as Record<string, unknown>;
      setFormData({
        default_export_format: (s.default_export_format as string) ?? "json",
        webhook_url: (s.webhook_url as string) ?? "",
        notifications_enabled: (s.notifications_enabled as boolean) ?? true,
        ai_analysis_enabled: (s.ai_analysis_enabled as boolean) ?? true,
        max_concurrent_scans: (s.max_concurrent_scans as number) ?? 3,
        ai_model: (s.ai_model as string) ?? "nemotron-3-super-free",
        smtp_host: (s.smtp_host as string) ?? "",
        smtp_port: (s.smtp_port as number) ?? 587,
        smtp_user: (s.smtp_user as string) ?? "",
        smtp_from: (s.smtp_from as string) ?? "noreply@bugfinder.io",
        slack_webhook_url: (s.slack_webhook_url as string) ?? "",
        teams_webhook_url: (s.teams_webhook_url as string) ?? "",
        pagerduty_routing_key: (s.pagerduty_routing_key as string) ?? "",
      });
      setApiKey((s.api_key as string) ?? "");
    }
  }, [settings]);

  const updateSettings = useUpdateSettings({
    mutation: {
      onSuccess: () => {
        toast({ title: "Settings saved", description: "Platform configuration updated successfully." });
      },
      onError: () => {
        toast({ title: "Error saving settings", variant: "destructive" });
      },
    },
  });

  async function regenerateApiKey() {
    setRegenerating(true);
    try {
      const r = await fetch("/api/settings/regenerate-api-key", { method: "POST", credentials: "include" });
      if (!r.ok) throw new Error("Failed");
      const d = await r.json() as { api_key: string };
      setApiKey(d.api_key);
      toast({ title: "API key regenerated", description: "Your new API key is ready." });
    } catch {
      toast({ title: "Failed to regenerate API key", variant: "destructive" });
    } finally { setRegenerating(false); }
  }

  async function testSmtp() {
    setSmtpTesting(true);
    try {
      const r = await fetch("/api/settings/test-smtp", { method: "POST", credentials: "include" });
      const d = await r.json() as { ok?: boolean; error?: string };
      if (d.ok) toast({ title: "SMTP test passed", description: "Test email sent successfully." });
      else toast({ title: "SMTP test failed", description: d.error ?? "Unknown error", variant: "destructive" });
    } catch {
      toast({ title: "SMTP test failed", description: "Could not reach server", variant: "destructive" });
    } finally { setSmtpTesting(false); }
  }

  if (isLoading) return <div className="p-8 text-center text-muted-foreground">Loading settings...</div>;

  return (
    <div className="max-w-4xl space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Platform Settings</h1>
        <p className="text-muted-foreground">Configure global platform behavior and integrations.</p>
      </div>

      <div className="grid gap-6">
        {/* Scan Engine */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center"><Activity className="w-5 h-5 mr-2 text-primary" />Engine Configuration</CardTitle>
            <CardDescription>Manage scan concurrency and behavior</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <Label>Maximum Concurrent Scans</Label>
                <span className="font-mono text-sm bg-muted px-2 py-1 rounded">{formData.max_concurrent_scans}</span>
              </div>
              <Slider value={[formData.max_concurrent_scans]} min={1} max={10} step={1}
                onValueChange={(val) => setFormData({ ...formData, max_concurrent_scans: val[0] })} />
              <p className="text-xs text-muted-foreground">Higher concurrency requires more system resources.</p>
            </div>
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label className="flex items-center"><BrainCircuit className="w-4 h-4 mr-2" />AI Analysis Engine</Label>
                <p className="text-sm text-muted-foreground">Auto-generate executive summaries for scan results.</p>
              </div>
              <Switch checked={formData.ai_analysis_enabled}
                onCheckedChange={(c) => setFormData({ ...formData, ai_analysis_enabled: c })} />
            </div>
          </CardContent>
        </Card>

        {/* AI Model */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center"><BrainCircuit className="w-5 h-5 mr-2 text-primary" />AI Model</CardTitle>
            <CardDescription>Select the AI model used for analysis and chat features</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>Active Model</Label>
              <Select value={formData.ai_model} onValueChange={(v) => setFormData({ ...formData, ai_model: v })}>
                <SelectTrigger>
                  <SelectValue placeholder="Select model" />
                </SelectTrigger>
                <SelectContent>
                  {AI_MODELS.map((m) => (
                    <SelectItem key={m.value} value={m.value}>{m.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">Changes take effect immediately without restart.</p>
            </div>
          </CardContent>
        </Card>

        {/* Integrations & Export */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center"><Webhook className="w-5 h-5 mr-2 text-primary" />Integrations & Export</CardTitle>
            <CardDescription>Configure external hooks and data formats</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="space-y-2">
              <Label>Global Webhook URL</Label>
              <Input placeholder="https://your-domain.com/webhook" value={formData.webhook_url}
                onChange={(e) => setFormData({ ...formData, webhook_url: e.target.value })} />
              <p className="text-xs text-muted-foreground">Called when high/critical findings are discovered or scans complete.</p>
            </div>
            <div className="space-y-2">
              <Label>Default Export Format</Label>
              <Select value={formData.default_export_format} onValueChange={(v) => setFormData({ ...formData, default_export_format: v })}>
                <SelectTrigger><SelectValue placeholder="Select format" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="json">JSON</SelectItem>
                  <SelectItem value="csv">CSV</SelectItem>
                  <SelectItem value="pdf">PDF Report</SelectItem>
                  <SelectItem value="html">HTML Report</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </CardContent>
        </Card>

        {/* SMTP */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center"><Mail className="w-5 h-5 mr-2 text-primary" />Email / SMTP</CardTitle>
            <CardDescription>Configure outbound email for password resets and alerts</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>SMTP Host</Label>
                <Input placeholder="smtp.example.com" value={formData.smtp_host}
                  onChange={(e) => setFormData({ ...formData, smtp_host: e.target.value })} />
              </div>
              <div className="space-y-2">
                <Label>SMTP Port</Label>
                <Input type="number" placeholder="587" value={formData.smtp_port}
                  onChange={(e) => setFormData({ ...formData, smtp_port: Number(e.target.value) })} />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>SMTP User</Label>
                <Input placeholder="user@example.com" value={formData.smtp_user}
                  onChange={(e) => setFormData({ ...formData, smtp_user: e.target.value })} />
              </div>
              <div className="space-y-2">
                <Label>From Address</Label>
                <Input placeholder="noreply@bugfinder.io" value={formData.smtp_from}
                  onChange={(e) => setFormData({ ...formData, smtp_from: e.target.value })} />
              </div>
            </div>
            <p className="text-xs text-muted-foreground">SMTP password is configured via the SMTP_PASS environment variable.</p>
            <Button variant="outline" size="sm" onClick={testSmtp} disabled={smtpTesting || !formData.smtp_host} className="gap-2">
              {smtpTesting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
              Test SMTP Connection
            </Button>
          </CardContent>
        </Card>

        {/* Notification Channels */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center"><Bell className="w-5 h-5 mr-2 text-primary" />Notification Channels</CardTitle>
            <CardDescription>Configure Slack, Teams, and PagerDuty for critical alert delivery</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>Slack Webhook URL</Label>
              <Input placeholder="https://hooks.slack.com/services/..." value={formData.slack_webhook_url}
                onChange={(e) => setFormData({ ...formData, slack_webhook_url: e.target.value })} />
            </div>
            <div className="space-y-2">
              <Label>Microsoft Teams Webhook URL</Label>
              <Input placeholder="https://outlook.office.com/webhook/..." value={formData.teams_webhook_url}
                onChange={(e) => setFormData({ ...formData, teams_webhook_url: e.target.value })} />
            </div>
            <div className="space-y-2">
              <Label>PagerDuty Routing Key</Label>
              <Input placeholder="your-pagerduty-routing-key" value={formData.pagerduty_routing_key}
                onChange={(e) => setFormData({ ...formData, pagerduty_routing_key: e.target.value })} />
              <p className="text-xs text-muted-foreground">Events API v2 integration key from your PagerDuty service.</p>
            </div>
          </CardContent>
        </Card>

        {/* Alerts */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center"><Bell className="w-5 h-5 mr-2 text-primary" />Alerts</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <Label>System Notifications</Label>
                <p className="text-sm text-muted-foreground">Receive UI alerts for important events.</p>
              </div>
              <Switch checked={formData.notifications_enabled}
                onCheckedChange={(c) => setFormData({ ...formData, notifications_enabled: c })} />
            </div>
          </CardContent>
        </Card>

        {/* Per-user notification preferences */}
        <NotificationPreferencesCard />

        {/* API Key */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center"><Key className="w-5 h-5 mr-2 text-primary" />API Access</CardTitle>
            <CardDescription>Use this key in the X-API-Key header for programmatic access</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex space-x-2">
              <div className="relative flex-1">
                <Input
                  value={apiKey}
                  readOnly
                  type={showApiKey ? "text" : "password"}
                  className="font-mono text-muted-foreground pr-10"
                />
                <button type="button" onClick={() => setShowApiKey(!showApiKey)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                  {showApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              <Button variant="outline" onClick={regenerateApiKey} disabled={regenerating}>
                <RefreshCw className={`w-4 h-4 mr-2 ${regenerating ? "animate-spin" : ""}`} />
                Regenerate
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* 2FA Setup */}
        <TwoFactorCard />

        <div className="flex justify-end">
          <Button onClick={() => updateSettings.mutate({ data: formData as Record<string, unknown> })}
            disabled={updateSettings.isPending} className="w-32">
            {updateSettings.isPending ? "Saving..." : <><Save className="w-4 h-4 mr-2" />Save All</>}
          </Button>
        </div>
      </div>
    </div>
  );
}

function NotificationPreferencesCard() {
  const { toast } = useToast();
  const { data, isLoading } = useQuery<Record<string, unknown>>({
    queryKey: ["/api/notifications/preferences"],
    queryFn: () => fetch("/api/notifications/preferences", { credentials: "include" }).then(r => r.json()),
  });

  const [channels, setChannels] = useState<string[]>([]);
  const [notifyCritical, setNotifyCritical] = useState(true);
  const [notifyHigh, setNotifyHigh] = useState(true);
  const [notifyScanComplete, setNotifyScanComplete] = useState(false);

  useEffect(() => {
    if (data) {
      setChannels((data.channels as string[]) ?? []);
      setNotifyCritical((data.notify_critical as boolean) ?? true);
      setNotifyHigh((data.notify_high as boolean) ?? true);
      setNotifyScanComplete((data.notify_scan_complete as boolean) ?? false);
    }
  }, [data]);

  const save = useMutation({
    mutationFn: () =>
      fetch("/api/notifications/preferences", {
        method: "PUT",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channels, notify_critical: notifyCritical, notify_high: notifyHigh, notify_scan_complete: notifyScanComplete }),
      }).then(r => r.json()),
    onSuccess: () => toast({ title: "Notification preferences saved" }),
    onError: () => toast({ title: "Failed to save preferences", variant: "destructive" }),
  });

  function toggleChannel(ch: string) {
    setChannels(prev => prev.includes(ch) ? prev.filter(c => c !== ch) : [...prev, ch]);
  }

  const CHANNELS = [
    { id: "email", label: "Email" },
    { id: "slack", label: "Slack" },
    { id: "teams", label: "Teams" },
    { id: "pagerduty", label: "PagerDuty" },
  ];

  if (isLoading) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center"><Bell className="w-5 h-5 mr-2 text-primary" />Notification Preferences</CardTitle>
        <CardDescription>Choose which channels and events trigger your personal notifications</CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        <div>
          <Label className="text-sm font-medium mb-2 block">Alert Channels</Label>
          <div className="flex flex-wrap gap-2">
            {CHANNELS.map(ch => (
              <button key={ch.id} onClick={() => toggleChannel(ch.id)}
                className={`text-sm px-3 py-1.5 rounded-md border transition-colors ${channels.includes(ch.id) ? "border-primary/60 bg-primary/10 text-primary" : "border-border text-muted-foreground hover:border-foreground/30"}`}>
                {ch.label}
              </button>
            ))}
          </div>
        </div>
        <div className="space-y-3">
          <Label className="text-sm font-medium block">Notify Me When</Label>
          {[
            { label: "Critical findings are discovered", value: notifyCritical, setter: setNotifyCritical },
            { label: "High findings are discovered", value: notifyHigh, setter: setNotifyHigh },
            { label: "A scan completes", value: notifyScanComplete, setter: setNotifyScanComplete },
          ].map(({ label, value, setter }) => (
            <div key={label} className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">{label}</span>
              <Switch checked={value} onCheckedChange={setter} />
            </div>
          ))}
        </div>
        <Button size="sm" onClick={() => save.mutate()} disabled={save.isPending} className="gap-2">
          {save.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
          Save Preferences
        </Button>
      </CardContent>
    </Card>
  );
}

function TwoFactorCard() {
  const { toast } = useToast();
  const [step, setStep] = useState<"idle" | "setup" | "verify">("idle");
  const [qrUrl, setQrUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [code, setCode] = useState("");

  const { data: twoFaStatus } = useQuery<{ enabled: boolean }>({
    queryKey: ["/api/auth/2fa/status"],
    queryFn: () => fetch("/api/auth/2fa/status", { credentials: "include" }).then(r => r.json()),
  });

  const setupMut = useMutation({
    mutationFn: () => fetch("/api/auth/2fa/setup", { method: "POST", credentials: "include" }).then(r => r.json()),
    onSuccess: (d) => { setQrUrl(d.qr_url ?? ""); setSecret(d.secret ?? ""); setStep("setup"); },
    onError: () => toast({ title: "Failed to start 2FA setup", variant: "destructive" }),
  });

  const verifyMut = useMutation({
    mutationFn: () => fetch("/api/auth/2fa/verify", {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    }).then(r => r.json()),
    onSuccess: (d) => {
      if (d.ok) { toast({ title: "2FA enabled!" }); setStep("idle"); setCode(""); }
      else toast({ title: "Invalid code", variant: "destructive" });
    },
  });

  const disableMut = useMutation({
    mutationFn: () => fetch("/api/auth/2fa/disable", { method: "POST", credentials: "include" }).then(r => r.json()),
    onSuccess: () => toast({ title: "2FA disabled" }),
  });

  const enabled = twoFaStatus?.enabled ?? false;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-primary" />Two-Factor Authentication
        </CardTitle>
        <CardDescription>Add an extra layer of security with TOTP (e.g. Google Authenticator)</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!enabled && step === "idle" && (
          <Button onClick={() => setupMut.mutate()} disabled={setupMut.isPending} variant="outline" className="gap-2">
            <QrCode className="w-4 h-4" />Enable 2FA
          </Button>
        )}
        {enabled && step === "idle" && (
          <div className="flex items-center gap-3">
            <span className="text-sm text-green-500 font-medium flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4" />2FA is active
            </span>
            <Button onClick={() => disableMut.mutate()} disabled={disableMut.isPending} variant="outline" size="sm" className="text-destructive border-destructive/30">
              Disable 2FA
            </Button>
          </div>
        )}
        {step === "setup" && (
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">Scan this QR code with your authenticator app:</p>
            {qrUrl && <img src={qrUrl} alt="2FA QR Code" className="w-40 h-40 rounded border border-border" />}
            <p className="text-xs text-muted-foreground">Or enter manually: <code className="font-mono bg-muted px-1 py-0.5 rounded">{secret}</code></p>
            <div className="flex gap-2 items-end">
              <div className="space-y-1">
                <Label className="text-xs">Enter 6-digit code</Label>
                <Input value={code} onChange={e => setCode(e.target.value)} placeholder="123456"
                  className="w-36 font-mono" maxLength={6} />
              </div>
              <Button onClick={() => verifyMut.mutate()} disabled={verifyMut.isPending || code.length < 6} size="sm">
                <Smartphone className="w-4 h-4 mr-1.5" />Verify & Enable
              </Button>
              <Button variant="ghost" size="sm" onClick={() => setStep("idle")}>Cancel</Button>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
