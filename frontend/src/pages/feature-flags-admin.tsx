import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Flag, RefreshCw, ToggleLeft, ToggleRight, Loader2, Users } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface FeatureFlag {
  name: string;
  enabled: boolean;
  description?: string;
  allowed_roles?: string[];
  rollout_percent?: number;
  updated_at?: string;
}

export default function FeatureFlagsAdmin() {
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: flags = [], isLoading, refetch } = useQuery<FeatureFlag[]>({
    queryKey: ["feature-flags"],
    queryFn: async () => {
      const res = await fetch("/api/feature-flags", { credentials: "include" });
      if (!res.ok) throw new Error("Failed to load");
      return res.json();
    },
  });

  const toggle = useMutation({
    mutationFn: async ({ name, enabled }: { name: string; enabled: boolean }) => {
      const res = await fetch(`/api/feature-flags/${name}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ enabled }),
      });
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    },
    onSuccess: (_, { name, enabled }) => {
      toast({ title: `Flag ${enabled ? "enabled" : "disabled"}`, description: name });
      qc.invalidateQueries({ queryKey: ["feature-flags"] });
    },
    onError: (e: Error) => toast({ title: "Update failed", description: e.message, variant: "destructive" }),
  });

  const updateRollout = useMutation({
    mutationFn: async ({ name, percent }: { name: string; percent: number }) => {
      const res = await fetch(`/api/feature-flags/${name}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ rollout_percent: percent }),
      });
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["feature-flags"] });
      toast({ title: "Rollout updated" });
    },
  });

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Flag className="w-6 h-6 text-primary" />
            Feature Flags
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Control feature rollouts per role, user, or percentage. Changes take effect within 30 seconds.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="w-4 h-4 mr-2" />Refresh
        </Button>
      </div>

      {isLoading ? (
        <div className="grid gap-4">
          {Array.from({ length: 5 }).map((_, i) => (
            <Card key={i} className="border-border/50">
              <CardContent className="p-4">
                <div className="h-4 bg-muted animate-pulse rounded w-1/3 mb-2" />
                <div className="h-3 bg-muted animate-pulse rounded w-2/3" />
              </CardContent>
            </Card>
          ))}
        </div>
      ) : flags.length === 0 ? (
        <Card className="border-border/50">
          <CardContent className="p-12 text-center">
            <Flag className="w-10 h-10 text-muted-foreground mx-auto mb-3" />
            <p className="text-muted-foreground">No feature flags configured yet.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-3">
          {flags.map(flag => (
            <Card key={flag.name} className={`border-border/50 transition-colors ${flag.enabled ? "border-green-500/30 bg-green-500/5" : ""}`}>
              <CardContent className="p-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <code className="text-sm font-mono font-semibold">{flag.name}</code>
                      {flag.enabled ? (
                        <Badge className="bg-green-500/20 text-green-400 border-green-500/30 text-xs">Enabled</Badge>
                      ) : (
                        <Badge variant="outline" className="text-xs text-muted-foreground">Disabled</Badge>
                      )}
                      {flag.rollout_percent !== undefined && flag.rollout_percent < 100 && (
                        <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30 text-xs">
                          {flag.rollout_percent}% rollout
                        </Badge>
                      )}
                      {flag.allowed_roles?.length && (
                        <Badge className="bg-purple-500/20 text-purple-400 border-purple-500/30 text-xs gap-1">
                          <Users className="w-2.5 h-2.5" />
                          {flag.allowed_roles.join(", ")}
                        </Badge>
                      )}
                    </div>
                    {flag.description && (
                      <p className="text-xs text-muted-foreground">{flag.description}</p>
                    )}
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    {/* Rollout percent stepper */}
                    {flag.enabled && (
                      <div className="flex items-center gap-1 text-xs">
                        <span className="text-muted-foreground">Rollout:</span>
                        <select
                          className="bg-background border border-border rounded px-1 py-0.5 text-xs"
                          value={flag.rollout_percent ?? 100}
                          onChange={e => updateRollout.mutate({ name: flag.name, percent: Number(e.target.value) })}>
                          {[10, 25, 50, 75, 100].map(p => (
                            <option key={p} value={p}>{p}%</option>
                          ))}
                        </select>
                      </div>
                    )}
                    <Button
                      variant="ghost"
                      size="sm"
                      className={flag.enabled ? "text-green-400 hover:text-green-300" : "text-muted-foreground"}
                      disabled={toggle.isPending}
                      onClick={() => toggle.mutate({ name: flag.name, enabled: !flag.enabled })}>
                      {toggle.isPending ? (
                        <Loader2 className="w-5 h-5 animate-spin" />
                      ) : flag.enabled ? (
                        <ToggleRight className="w-6 h-6" />
                      ) : (
                        <ToggleLeft className="w-6 h-6" />
                      )}
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
