import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { KeyRound, Eye, EyeOff, TestTube2, Plus, Trash2, RefreshCw } from "lucide-react";
import { formatDistanceToNow } from "date-fns";

// ── Types ─────────────────────────────────────────────────────────────────────

type CredentialType = "basic_auth" | "api_key" | "oauth_token" | "cookie" | "certificate";

interface Credential {
  id: string;
  name: string;
  type: CredentialType;
  username?: string;
  masked_value: string;
  targets: string[];
  created_at: string;
  last_used: string | null;
}

// ── Type badge colors ─────────────────────────────────────────────────────────

const TYPE_META: Record<CredentialType, { label: string; cls: string }> = {
  basic_auth:   { label: "Basic Auth",   cls: "text-blue-400 border-blue-400/30 bg-blue-400/10" },
  api_key:      { label: "API Key",      cls: "text-purple-400 border-purple-400/30 bg-purple-400/10" },
  oauth_token:  { label: "OAuth Token",  cls: "text-green-400 border-green-400/30 bg-green-400/10" },
  cookie:       { label: "Cookie",       cls: "text-orange-400 border-orange-400/30 bg-orange-400/10" },
  certificate:  { label: "Certificate",  cls: "text-yellow-400 border-yellow-400/30 bg-yellow-400/10" },
};

// ── Single credential card ─────────────────────────────────────────────────────

function CredentialCard({
  cred,
  onDelete,
}: {
  cred: Credential;
  onDelete: () => void;
}) {
  const { toast } = useToast();
  const [revealed, setRevealed] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);
  const [testing, setTesting] = useState(false);

  const meta = TYPE_META[cred.type] ?? { label: cred.type, cls: "" };

  async function handleTest() {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await fetch(`/api/credentials/${cred.id}/test`, {
        method: "POST",
        credentials: "include",
      });
      const data = await res.json();
      setTestResult(data);
    } catch {
      setTestResult({ ok: false, message: "Request failed" });
    } finally {
      setTesting(false);
    }
  }

  const lastUsed = cred.last_used
    ? formatDistanceToNow(new Date(cred.last_used), { addSuffix: true })
    : "Never";

  return (
    <Card className="flex flex-col">
      <CardContent className="p-4 flex flex-col gap-3 h-full">
        {/* Header */}
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2 flex-wrap">
            <Badge variant="outline" className={`text-xs ${meta.cls}`}>
              {meta.label}
            </Badge>
          </div>
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-destructive hover:text-destructive flex-shrink-0"
            onClick={onDelete}
          >
            <Trash2 className="w-3.5 h-3.5" />
          </Button>
        </div>

        {/* Name */}
        <p className="font-semibold text-sm leading-tight">{cred.name}</p>

        {/* Username (basic_auth) */}
        {cred.type === "basic_auth" && cred.username && (
          <p className="text-xs text-muted-foreground font-mono">user: {cred.username}</p>
        )}

        {/* Masked value with eye toggle */}
        {(cred.type === "api_key" || cred.type === "oauth_token") && (
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-muted-foreground flex-1 truncate">
              {revealed ? cred.masked_value : "••••••••••••••••"}
            </span>
            <button
              className="text-muted-foreground hover:text-foreground transition-colors flex-shrink-0"
              onClick={() => setRevealed(v => !v)}
            >
              {revealed ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
            </button>
          </div>
        )}

        {/* Associated targets */}
        {cred.targets.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {cred.targets.slice(0, 3).map(t => (
              <span
                key={t}
                className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground font-mono truncate max-w-[120px]"
                title={t}
              >
                {t}
              </span>
            ))}
            {cred.targets.length > 3 && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">
                +{cred.targets.length - 3}
              </span>
            )}
          </div>
        )}

        {/* Last used */}
        <p className="text-[11px] text-muted-foreground mt-auto">Last used: {lastUsed}</p>

        {/* Test connection */}
        <div className="space-y-1.5">
          <Button
            variant="outline"
            size="sm"
            className="w-full h-7 text-xs"
            onClick={handleTest}
            disabled={testing}
          >
            <TestTube2 className="w-3.5 h-3.5 mr-1.5" />
            {testing ? "Testing…" : "Test Connection"}
          </Button>
          {testResult && (
            <p
              className={`text-[11px] text-center font-medium ${testResult.ok ? "text-green-400" : "text-red-400"}`}
            >
              {testResult.ok ? "✓" : "✗"} {testResult.message}
            </p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ── Add Credential dialog ─────────────────────────────────────────────────────

const EMPTY_FORM = {
  name: "",
  type: "basic_auth" as CredentialType,
  username: "",
  password: "",
  token: "",
  cookie: "",
  cert: "",
};

function AddCredentialDialog({
  open,
  onClose,
  onSave,
  saving,
}: {
  open: boolean;
  onClose: () => void;
  onSave: (data: typeof EMPTY_FORM) => void;
  saving: boolean;
}) {
  const [form, setForm] = useState({ ...EMPTY_FORM });
  const set = (field: string, value: string) =>
    setForm(p => ({ ...p, [field]: value }));

  function handleSave() {
    onSave(form);
  }

  return (
    <Dialog open={open} onOpenChange={v => !v && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Add Credential</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 py-2">
          {/* Name */}
          <div className="space-y-1.5">
            <Label htmlFor="cred-name">Name *</Label>
            <Input
              id="cred-name"
              placeholder="Production API Key"
              value={form.name}
              onChange={e => set("name", e.target.value)}
            />
          </div>

          {/* Type */}
          <div className="space-y-1.5">
            <Label htmlFor="cred-type">Type *</Label>
            <select
              id="cred-type"
              className="w-full h-9 rounded-md border border-input bg-background px-3 py-1 text-sm"
              value={form.type}
              onChange={e => setForm(p => ({ ...p, type: e.target.value as CredentialType }))}
            >
              <option value="basic_auth">Basic Auth</option>
              <option value="api_key">API Key</option>
              <option value="oauth_token">OAuth Token</option>
              <option value="cookie">Cookie</option>
              <option value="certificate">Certificate</option>
            </select>
          </div>

          {/* Conditional fields */}
          {form.type === "basic_auth" && (
            <>
              <div className="space-y-1.5">
                <Label>Username</Label>
                <Input
                  placeholder="admin"
                  value={form.username}
                  onChange={e => set("username", e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label>Password</Label>
                <Input
                  type="password"
                  placeholder="••••••••"
                  value={form.password}
                  onChange={e => set("password", e.target.value)}
                />
              </div>
            </>
          )}

          {form.type === "api_key" && (
            <>
              <div className="space-y-1.5">
                <Label>Key Name</Label>
                <Input
                  placeholder="X-API-Key"
                  value={form.username}
                  onChange={e => set("username", e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label>API Key Value</Label>
                <Input
                  type="password"
                  placeholder="sk-…"
                  value={form.token}
                  onChange={e => set("token", e.target.value)}
                />
              </div>
            </>
          )}

          {form.type === "oauth_token" && (
            <div className="space-y-1.5">
              <Label>Token</Label>
              <Input
                type="password"
                placeholder="Bearer token"
                value={form.token}
                onChange={e => set("token", e.target.value)}
              />
            </div>
          )}

          {form.type === "cookie" && (
            <div className="space-y-1.5">
              <Label>Cookie String</Label>
              <textarea
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm resize-none h-24"
                placeholder="session=abc123; csrf=xyz"
                value={form.cookie}
                onChange={e => set("cookie", e.target.value)}
              />
            </div>
          )}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button onClick={handleSave} disabled={!form.name.trim() || saving}>
            {saving ? "Saving…" : "Save"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function CredentialsPage() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);

  const { data: credentials = [], isLoading, refetch } = useQuery<Credential[]>({
    queryKey: ["/api/credentials"],
    queryFn: () =>
      fetch("/api/credentials", { credentials: "include" }).then(r => r.json()),
  });

  const createCredential = useMutation({
    mutationFn: (body: object) =>
      fetch("/api/credentials", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/credentials"] });
      toast({ title: "Credential saved" });
      setDialogOpen(false);
    },
    onError: () => {
      toast({ title: "Failed to save credential", variant: "destructive" });
    },
  });

  const deleteCredential = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/credentials/${id}`, {
        method: "DELETE",
        credentials: "include",
      }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/credentials"] });
      toast({ title: "Credential deleted" });
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64 text-muted-foreground">
        <RefreshCw className="w-5 h-5 animate-spin mr-2" /> Loading credentials…
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
            <KeyRound className="w-7 h-7" />
            Credential Vault
          </h1>
          <p className="text-muted-foreground mt-1">
            Manage scan credentials for authenticated testing.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="w-4 h-4 mr-1.5" /> Refresh
          </Button>
          <Button size="sm" onClick={() => setDialogOpen(true)}>
            <Plus className="w-4 h-4 mr-1.5" /> Add Credential
          </Button>
        </div>
      </div>

      {/* Grid */}
      {credentials.length === 0 ? (
        <div className="text-center py-20 text-muted-foreground text-sm">
          <KeyRound className="w-12 h-12 mx-auto mb-3 opacity-20" />
          <p className="font-medium mb-1">No credentials yet</p>
          <p className="text-xs">Add credentials to enable authenticated scanning.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {credentials.map(cred => (
            <CredentialCard
              key={cred.id}
              cred={cred}
              onDelete={() => {
                if (confirm(`Delete credential "${cred.name}"?`)) {
                  deleteCredential.mutate(cred.id);
                }
              }}
            />
          ))}
        </div>
      )}

      <AddCredentialDialog
        open={dialogOpen}
        onClose={() => setDialogOpen(false)}
        onSave={data => createCredential.mutate(data)}
        saving={createCredential.isPending}
      />
    </div>
  );
}
