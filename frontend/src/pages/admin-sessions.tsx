import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Activity, Trash2, Loader2, RefreshCw } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface Session {
  id: string;
  user_id?: string;
  username?: string;
  role?: string;
  expires?: string;
  created_at?: string;
}

export default function AdminSessions() {
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: sessions = [], isLoading, refetch } = useQuery<Session[]>({
    queryKey: ["/api/admin/sessions"],
    queryFn: () => fetch("/api/admin/sessions", { credentials: "include" }).then(r => r.json()),
    refetchInterval: 30000,
  });

  const revokeMutation = useMutation({
    mutationFn: (id: string) => fetch(`/api/admin/sessions/${id}`, { method: "DELETE", credentials: "include" }).then(r => r.json()),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["/api/admin/sessions"] }); toast({ title: "Session revoked" }); },
    onError: () => toast({ title: "Failed to revoke session", variant: "destructive" }),
  });

  const list = Array.isArray(sessions) ? sessions : [];
  const ROLE_COLORS: Record<string, string> = { admin: "#f87171", senior: "#fb923c", analyst: "#60a5fa", viewer: "#94a3b8" };

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Activity className="w-6 h-6 text-purple-400" /> Active Sessions
          </h1>
          <p className="text-muted-foreground mt-1 text-sm">
            View and revoke active user sessions across the platform.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="w-4 h-4 mr-1" /> Refresh
        </Button>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-12"><Loader2 className="w-6 h-6 animate-spin text-muted-foreground" /></div>
      ) : list.length === 0 ? (
        <Card>
          <CardContent className="py-10 text-center text-muted-foreground text-sm">
            No active sessions found.
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <div className="divide-y" style={{ borderColor: "hsl(var(--border))" }}>
              <div className="grid grid-cols-5 gap-3 px-4 py-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                <span>Username</span>
                <span>Role</span>
                <span>User ID</span>
                <span>Expires</span>
                <span className="text-right">Action</span>
              </div>
              {list.map(sess => (
                <div key={sess.id} className="grid grid-cols-5 gap-3 px-4 py-3 items-center text-sm">
                  <span className="font-medium">{sess.username ?? "—"}</span>
                  <span>
                    {sess.role ? (
                      <Badge variant="outline" className="text-[11px]"
                        style={{ color: ROLE_COLORS[sess.role] ?? "#94a3b8", borderColor: `${ROLE_COLORS[sess.role] ?? "#94a3b8"}40` }}>
                        {sess.role}
                      </Badge>
                    ) : "—"}
                  </span>
                  <span className="text-xs text-muted-foreground font-mono truncate">{sess.user_id ?? "—"}</span>
                  <span className="text-xs text-muted-foreground">
                    {sess.expires ? new Date(sess.expires).toLocaleString() : "—"}
                  </span>
                  <div className="flex justify-end">
                    <Button
                      variant="ghost" size="sm"
                      className="text-red-400 hover:text-red-300 h-7 px-2"
                      onClick={() => revokeMutation.mutate(sess.id)}
                      disabled={revokeMutation.isPending}
                    >
                      <Trash2 className="w-3.5 h-3.5 mr-1" /> Revoke
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
