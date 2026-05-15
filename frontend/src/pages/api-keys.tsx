import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Plus, Trash2, Copy, Check, Key, Clock, KeyRound, AlertTriangle } from "lucide-react";
import { format, differenceInDays } from "date-fns";
import { useToast } from "@/hooks/use-toast";

const SCOPES = [
  "read:findings", "write:findings", "read:scans", "write:scans",
  "read:targets", "write:targets", "read:reports", "admin:users",
  "admin:settings", "admin:api-keys",
];

interface ApiKey {
  id: string; name: string; key_preview: string;
  scopes: string[]; active: boolean; last_used: string | null;
  last_used_at?: string | null;
  usage_count: number; created_at: string; expires_at?: string | null;
}

function LastUsedLabel({ lastUsed }: { lastUsed: string | null | undefined }) {
  if (!lastUsed) return <span>Never used</span>;
  const days = differenceInDays(new Date(), new Date(lastUsed));
  if (days === 0) return <span className="flex items-center gap-1"><Clock className="w-3 h-3" />Last used today</span>;
  if (days === 1) return <span className="flex items-center gap-1"><Clock className="w-3 h-3" />Last used yesterday</span>;
  return <span className="flex items-center gap-1"><Clock className="w-3 h-3" />Last used {days} days ago</span>;
}

function ScopeBadges({ scopes }: { scopes: string[] }) {
  const visible = scopes.slice(0, 3);
  const extra = scopes.length - 3;
  return (
    <div className="flex flex-wrap gap-1 mt-2">
      {visible.map((s) => (
        <Badge key={s} variant="secondary" className="text-[10px]">{s}</Badge>
      ))}
      {extra > 0 && (
        <Badge variant="outline" className="text-[10px] text-muted-foreground">+{extra} more</Badge>
      )}
    </div>
  );
}

export default function ApiKeys() {
  const [createOpen, setCreateOpen] = useState(false);
  const [keyName, setKeyName] = useState("");
  const [selectedScopes, setSelectedScopes] = useState<string[]>([]);
  const [expiresAt, setExpiresAt] = useState("");
  const [newKeyValue, setNewKeyValue] = useState<string | null>(null);
  const [revokeId, setRevokeId] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: keys, isLoading } = useQuery<ApiKey[]>({
    queryKey: ["api-keys"],
    queryFn: () => fetch("/api/api-keys", { credentials: "include" }).then((r) => r.json()),
  });

  const createMut = useMutation({
    mutationFn: (payload: { name: string; scopes: string[]; expires_at?: string }) =>
      fetch("/api/api-keys", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      }).then((r) => r.json()),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ["api-keys"] });
      setNewKeyValue(data.key ?? data.api_key ?? null);
      setKeyName("");
      setSelectedScopes([]);
      setExpiresAt("");
    },
    onError: () => toast({ title: "Failed to create API key", variant: "destructive" }),
  });

  const revokeMut = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/api-keys/${id}`, { method: "DELETE", credentials: "include" }).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["api-keys"] });
      setRevokeId(null);
      toast({ title: "API key revoked" });
    },
  });

  async function copyKey(key: string) {
    await navigator.clipboard.writeText(key);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function toggleScope(scope: string) {
    setSelectedScopes((prev) =>
      prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope]
    );
  }

  function handleCreate() {
    if (!keyName) return;
    const payload: { name: string; scopes: string[]; expires_at?: string } = {
      name: keyName,
      scopes: selectedScopes,
    };
    if (expiresAt) payload.expires_at = expiresAt;
    createMut.mutate(payload);
  }

  function handleDialogClose(open: boolean) {
    setCreateOpen(open);
    if (!open) {
      setNewKeyValue(null);
      setKeyName("");
      setSelectedScopes([]);
      setExpiresAt("");
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">API Keys</h1>
          <p className="text-sm text-muted-foreground">Manage API keys for programmatic access</p>
        </div>
        <Button onClick={() => setCreateOpen(true)} className="gap-2">
          <Plus className="w-4 h-4" /> Generate New Key
        </Button>
      </div>

      {/* Usage instructions */}
      <Card>
        <CardHeader><CardTitle className="text-sm">Usage</CardTitle></CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground mb-2">Include your API key in request headers:</p>
          <div className="bg-muted rounded-md p-3 font-mono text-xs text-foreground">
            <span className="text-purple-400">curl</span>{" "}
            <span className="text-green-400">-H</span>{" "}
            <span className="text-yellow-400">"X-API-Key: your-api-key"</span>{" "}
            https://your-instance.com/api/findings
          </div>
        </CardContent>
      </Card>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading...</p>
      ) : !keys || keys.length === 0 ? (
        /* Empty state */
        <Card>
          <CardContent className="py-16 flex flex-col items-center gap-4 text-center">
            <div className="w-14 h-14 rounded-2xl bg-muted flex items-center justify-center">
              <KeyRound className="w-7 h-7 text-muted-foreground" />
            </div>
            <div className="space-y-1">
              <p className="font-semibold text-foreground">No API keys yet</p>
              <p className="text-sm text-muted-foreground max-w-xs">
                Create your first API key to enable programmatic access
              </p>
            </div>
            <Button onClick={() => setCreateOpen(true)} className="gap-2">
              <Plus className="w-4 h-4" /> Create API Key
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {keys.map((key) => (
            <Card key={key.id}>
              <CardContent className="py-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <Key className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                      <span className="font-semibold text-foreground">{key.name}</span>
                      <Badge variant={key.active ? "default" : "secondary"} className="text-[10px]">
                        {key.active ? "Active" : "Inactive"}
                      </Badge>
                    </div>
                    <p className="font-mono text-xs text-muted-foreground">{key.key_preview}</p>
                    <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                      <span>Created {format(new Date(key.created_at), "MMM d, yyyy")}</span>
                      <LastUsedLabel lastUsed={key.last_used_at ?? key.last_used} />
                      <span>Used {key.usage_count} times</span>
                      {key.expires_at && (
                        <span>Expires {format(new Date(key.expires_at), "MMM d, yyyy")}</span>
                      )}
                    </div>
                    <ScopeBadges scopes={key.scopes} />
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setRevokeId(key.id)}
                    className="text-destructive hover:text-destructive hover:bg-destructive/10 flex-shrink-0"
                  >
                    <Trash2 className="w-4 h-4" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Create dialog */}
      <Dialog open={createOpen} onOpenChange={handleDialogClose}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>{newKeyValue ? "API Key Created" : "Generate API Key"}</DialogTitle>
          </DialogHeader>

          {newKeyValue ? (
            /* One-time reveal */
            <div className="space-y-4">
              <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-3">
                <div className="flex items-start gap-2 mb-3">
                  <AlertTriangle className="w-4 h-4 text-yellow-500 flex-shrink-0 mt-0.5" />
                  <p className="text-xs font-semibold text-yellow-500">
                    This is the only time you'll see this key — copy it now. It will not be shown again.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <code className="flex-1 text-xs font-mono text-foreground bg-background/70 px-2 py-1.5 rounded overflow-x-auto break-all">
                    {newKeyValue}
                  </code>
                  <Button size="sm" variant="outline" onClick={() => copyKey(newKeyValue)} className="flex-shrink-0">
                    {copied ? <Check className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
                  </Button>
                </div>
              </div>
              <DialogFooter>
                <Button onClick={() => { setCreateOpen(false); setNewKeyValue(null); }}>Done</Button>
              </DialogFooter>
            </div>
          ) : (
            /* Create form */
            <div className="space-y-4">
              <div>
                <label className="text-xs font-medium text-muted-foreground">Key Name *</label>
                <Input
                  value={keyName}
                  onChange={(e) => setKeyName(e.target.value)}
                  placeholder="e.g., CI/CD Pipeline"
                  className="mt-1"
                  onKeyDown={(e) => e.key === "Enter" && keyName && handleCreate()}
                />
              </div>

              {/* Scope selection */}
              <div>
                <label className="text-xs font-medium text-muted-foreground block mb-2">Scopes</label>
                <div className="grid grid-cols-2 gap-2">
                  {SCOPES.map((scope) => (
                    <label key={scope} className="flex items-center gap-2 cursor-pointer group">
                      <Checkbox
                        checked={selectedScopes.includes(scope)}
                        onCheckedChange={() => toggleScope(scope)}
                        id={`scope-${scope}`}
                      />
                      <span className="text-xs text-foreground font-mono group-hover:text-primary transition-colors">
                        {scope}
                      </span>
                    </label>
                  ))}
                </div>
                {selectedScopes.length === 0 && (
                  <p className="text-[10px] text-muted-foreground mt-1">No scopes selected — key will have no permissions.</p>
                )}
              </div>

              {/* Expiry date */}
              <div>
                <label className="text-xs font-medium text-muted-foreground">Expires at (optional)</label>
                <Input
                  type="date"
                  value={expiresAt}
                  onChange={(e) => setExpiresAt(e.target.value)}
                  className="mt-1"
                  min={format(new Date(), "yyyy-MM-dd")}
                />
              </div>

              <DialogFooter>
                <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
                <Button onClick={handleCreate} disabled={!keyName || createMut.isPending}>
                  {createMut.isPending ? "Generating..." : "Generate"}
                </Button>
              </DialogFooter>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Revoke confirmation dialog */}
      <Dialog open={!!revokeId} onOpenChange={(o) => !o && setRevokeId(null)}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Revoke API Key</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-muted-foreground">
            This will permanently delete the API key. Any applications using it will lose access.
          </p>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRevokeId(null)}>Cancel</Button>
            <Button
              variant="destructive"
              onClick={() => revokeId && revokeMut.mutate(revokeId)}
              disabled={revokeMut.isPending}
            >
              {revokeMut.isPending ? "Revoking..." : "Revoke Key"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
