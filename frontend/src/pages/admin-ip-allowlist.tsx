import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Shield, Plus, Trash2, Loader2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface IpEntry { id: string; cidr: string; label: string; created_at: string; }

export default function AdminIpAllowlist() {
  const [cidr, setCidr] = useState("");
  const [label, setLabel] = useState("");
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: entries = [], isLoading } = useQuery<IpEntry[]>({
    queryKey: ["/api/admin/ip-allowlist"],
    queryFn: () => fetch("/api/admin/ip-allowlist", { credentials: "include" }).then(r => r.json()),
  });

  const addMutation = useMutation({
    mutationFn: () => fetch("/api/admin/ip-allowlist", {
      method: "POST", credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cidr, label }),
    }).then(r => r.json()),
    onSuccess: (data: { error?: string }) => {
      if (data.error) { toast({ title: data.error, variant: "destructive" }); return; }
      qc.invalidateQueries({ queryKey: ["/api/admin/ip-allowlist"] });
      setCidr(""); setLabel("");
      toast({ title: "IP entry added" });
    },
    onError: () => toast({ title: "Failed to add entry", variant: "destructive" }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => fetch(`/api/admin/ip-allowlist/${id}`, { method: "DELETE", credentials: "include" }).then(r => r.json()),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["/api/admin/ip-allowlist"] }); toast({ title: "Entry removed" }); },
  });

  const list = Array.isArray(entries) ? entries : [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <Shield className="w-6 h-6 text-green-400" /> IP Allowlist
        </h1>
        <p className="text-muted-foreground mt-1 text-sm">
          Restrict platform access to specific IP addresses or CIDR ranges. Leave empty to allow all IPs.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Add IP / CIDR Range</CardTitle>
          <CardDescription>Examples: 192.168.1.0/24, 10.0.0.1, 2001:db8::/32</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2">
            <Input
              placeholder="192.168.1.0/24"
              value={cidr}
              onChange={e => setCidr(e.target.value)}
              className="font-mono w-48"
            />
            <Input
              placeholder="Label (optional)"
              value={label}
              onChange={e => setLabel(e.target.value)}
              className="flex-1"
            />
            <Button onClick={() => addMutation.mutate()} disabled={!cidr || addMutation.isPending}>
              {addMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
            </Button>
          </div>
        </CardContent>
      </Card>

      {isLoading ? (
        <div className="flex justify-center py-8"><Loader2 className="w-6 h-6 animate-spin text-muted-foreground" /></div>
      ) : list.length === 0 ? (
        <Card>
          <CardContent className="py-10 text-center text-muted-foreground text-sm">
            No IP restrictions configured — all IPs are allowed.
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <div className="divide-y" style={{ borderColor: "hsl(var(--border))" }}>
              {list.map(entry => (
                <div key={entry.id} className="flex items-center px-4 py-3 gap-3">
                  <code className="font-mono text-sm font-medium flex-shrink-0">{entry.cidr}</code>
                  {entry.label && <Badge variant="outline" className="text-xs">{entry.label}</Badge>}
                  <span className="ml-auto text-xs text-muted-foreground">{new Date(entry.created_at).toLocaleDateString()}</span>
                  <Button
                    variant="ghost" size="sm"
                    className="text-red-400 hover:text-red-300 h-7 px-2"
                    onClick={() => deleteMutation.mutate(entry.id)}
                    disabled={deleteMutation.isPending}
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </Button>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
