import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Plus, Trash2, Copy, Check, Key, Clock } from "lucide-react";
import { format } from "date-fns";
import { useToast } from "@/hooks/use-toast";

interface ApiKey {
  id: string; name: string; key_preview: string;
  scopes: string[]; active: boolean; last_used: string | null;
  usage_count: number; created_at: string;
}

export default function ApiKeys() {
  const [createOpen, setCreateOpen] = useState(false);
  const [keyName, setKeyName] = useState("");
  const [newKey, setNewKey] = useState<string | null>(null);
  const [revokeId, setRevokeId] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: keys, isLoading } = useQuery<ApiKey[]>({
    queryKey: ["api-keys"],
    queryFn: () => fetch("/api/api-keys", { credentials: "include" }).then((r) => r.json()),
  });

  const createMut = useMutation({
    mutationFn: (name: string) =>
      fetch("/api/api-keys", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name }),
      }).then((r) => r.json()),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ["api-keys"] });
      setNewKey(data.key);
      setKeyName("");
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
        <Card>
          <CardContent className="py-10 text-center">
            <Key className="w-8 h-8 text-muted-foreground mx-auto mb-3" />
            <p className="text-muted-foreground">No API keys yet.</p>
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
                      {key.last_used ? (
                        <span className="flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          Last used {format(new Date(key.last_used), "MMM d, yyyy")}
                        </span>
                      ) : (
                        <span>Never used</span>
                      )}
                      <span>Used {key.usage_count} times</span>
                    </div>
                    <div className="flex gap-1 mt-2">
                      {key.scopes.map((s) => (
                        <Badge key={s} variant="secondary" className="text-[10px]">{s}</Badge>
                      ))}
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setRevokeId(key.id)}
                    className="text-red-400 hover:text-red-300 hover:bg-red-500/10 flex-shrink-0"
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
      <Dialog open={createOpen} onOpenChange={(o) => { setCreateOpen(o); if (!o) setNewKey(null); }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>{newKey ? "API Key Created" : "Generate API Key"}</DialogTitle>
          </DialogHeader>
          {newKey ? (
            <div className="space-y-4">
              <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-3">
                <p className="text-xs font-semibold text-yellow-400 mb-2">Store this key securely — it will not be shown again.</p>
                <div className="flex items-center gap-2">
                  <code className="flex-1 text-xs font-mono text-foreground bg-muted px-2 py-1.5 rounded overflow-x-auto">{newKey}</code>
                  <Button size="sm" variant="outline" onClick={() => copyKey(newKey)} className="flex-shrink-0">
                    {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
                  </Button>
                </div>
              </div>
              <DialogFooter>
                <Button onClick={() => { setCreateOpen(false); setNewKey(null); }}>Done</Button>
              </DialogFooter>
            </div>
          ) : (
            <>
              <div>
                <label className="text-xs font-medium text-muted-foreground">Key Name *</label>
                <Input
                  value={keyName}
                  onChange={(e) => setKeyName(e.target.value)}
                  placeholder="e.g., CI/CD Pipeline"
                  className="mt-1"
                  onKeyDown={(e) => e.key === "Enter" && keyName && createMut.mutate(keyName)}
                />
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
                <Button onClick={() => createMut.mutate(keyName)} disabled={!keyName || createMut.isPending}>
                  {createMut.isPending ? "Generating..." : "Generate"}
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* Revoke confirmation dialog */}
      <Dialog open={!!revokeId} onOpenChange={(o) => !o && setRevokeId(null)}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Revoke API Key</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-muted-foreground">This will permanently delete the API key. Any applications using it will lose access.</p>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRevokeId(null)}>Cancel</Button>
            <Button variant="destructive" onClick={() => revokeId && revokeMut.mutate(revokeId)} disabled={revokeMut.isPending}>
              {revokeMut.isPending ? "Revoking..." : "Revoke Key"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
