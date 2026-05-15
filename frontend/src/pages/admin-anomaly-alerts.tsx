import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, CheckCircle2, Loader2, RefreshCw, Eye } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface AnomalyAlert {
  id: string;
  type: string;
  user_id?: string;
  details: Record<string, unknown>;
  acknowledged: boolean;
  created_at: string;
}

const ALERT_TYPE_COLORS: Record<string, string> = {
  BULK_DELETE: "#f87171",
  RAPID_FIRE_EVENTS: "#fb923c",
  REPEATED_LOGIN_FAILURE: "#facc15",
  PRIVILEGE_ESCALATION: "#ef4444",
  AFTER_HOURS_LOGIN: "#a78bfa",
};

const ALERT_TYPE_LABELS: Record<string, string> = {
  BULK_DELETE: "Bulk Delete",
  RAPID_FIRE_EVENTS: "Rapid Fire",
  REPEATED_LOGIN_FAILURE: "Login Brute Force",
  PRIVILEGE_ESCALATION: "Privilege Escalation",
  AFTER_HOURS_LOGIN: "After-Hours Login",
};

export default function AdminAnomalyAlerts() {
  const [showUnackOnly, setShowUnackOnly] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: alerts = [], isLoading, refetch } = useQuery<AnomalyAlert[]>({
    queryKey: ["/api/admin/anomaly-alerts", showUnackOnly],
    queryFn: () => fetch(`/api/admin/anomaly-alerts?unack=${showUnackOnly}&limit=100`, { credentials: "include" }).then(r => r.json()),
    refetchInterval: 30000,
  });

  const ackMutation = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/admin/anomaly-alerts/${id}/acknowledge`, { method: "POST", credentials: "include" }).then(r => r.json()),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["/api/admin/anomaly-alerts"] }); toast({ title: "Alert acknowledged" }); },
  });

  const ackAllMutation = useMutation({
    mutationFn: () =>
      fetch("/api/admin/anomaly-alerts/acknowledge-all", { method: "POST", credentials: "include" }).then(r => r.json()),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["/api/admin/anomaly-alerts"] }); toast({ title: "All alerts acknowledged" }); },
  });

  const unacked = Array.isArray(alerts) ? alerts.filter(a => !a.acknowledged).length : 0;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <AlertTriangle className="w-6 h-6 text-red-400" /> Anomaly Alerts
          </h1>
          <p className="text-muted-foreground mt-1 text-sm">
            Security anomalies detected by the automated monitoring engine.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="w-4 h-4 mr-1" /> Refresh
          </Button>
          {unacked > 0 && (
            <Button size="sm" onClick={() => ackAllMutation.mutate()} disabled={ackAllMutation.isPending}>
              {ackAllMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-1" /> : <CheckCircle2 className="w-4 h-4 mr-1" />}
              Acknowledge All ({unacked})
            </Button>
          )}
        </div>
      </div>

      <div className="flex items-center gap-3">
        <Button
          variant={!showUnackOnly ? "default" : "outline"}
          size="sm"
          onClick={() => setShowUnackOnly(false)}
        >
          All Alerts
        </Button>
        <Button
          variant={showUnackOnly ? "default" : "outline"}
          size="sm"
          onClick={() => setShowUnackOnly(true)}
        >
          Unacknowledged {unacked > 0 && <Badge className="ml-1 bg-red-500 text-white text-[10px] px-1 py-0">{unacked}</Badge>}
        </Button>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-12">
          <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
        </div>
      ) : !Array.isArray(alerts) || alerts.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground text-sm">
            <CheckCircle2 className="w-8 h-8 mx-auto mb-3 text-green-400" />
            No anomaly alerts found.
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {alerts.map(alert => {
            const color = ALERT_TYPE_COLORS[alert.type] ?? "#94a3b8";
            const label = ALERT_TYPE_LABELS[alert.type] ?? alert.type;
            const isExpanded = expanded === alert.id;

            return (
              <Card key={alert.id} className={`border transition-all ${alert.acknowledged ? "opacity-60" : ""}`}
                style={{ borderColor: alert.acknowledged ? "hsl(var(--border))" : `${color}40` }}>
                <CardContent className="p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-start gap-3 flex-1 min-w-0">
                      <div className="w-2.5 h-2.5 rounded-full mt-1.5 flex-shrink-0"
                        style={{ background: alert.acknowledged ? "#4b5563" : color }} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-semibold text-sm" style={{ color }}>{label}</span>
                          {alert.acknowledged && <Badge variant="outline" className="text-[10px] py-0">Acknowledged</Badge>}
                        </div>
                        <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                          {alert.user_id && <span>User: {alert.user_id}</span>}
                          {(alert.details as Record<string, unknown>)?.["ip"] && (
                            <span>IP: {String((alert.details as Record<string, unknown>)["ip"])}</span>
                          )}
                          <span>{new Date(alert.created_at).toLocaleString()}</span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <Button variant="ghost" size="sm" className="h-7 px-2" onClick={() => setExpanded(isExpanded ? null : alert.id)}>
                        <Eye className="w-3.5 h-3.5" />
                      </Button>
                      {!alert.acknowledged && (
                        <Button size="sm" variant="outline" className="h-7 text-xs"
                          onClick={() => ackMutation.mutate(alert.id)}
                          disabled={ackMutation.isPending}>
                          {ackMutation.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : "Acknowledge"}
                        </Button>
                      )}
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="mt-3 pt-3 border-t" style={{ borderColor: "hsl(var(--border))" }}>
                      <pre className="text-[11px] font-mono rounded p-3 overflow-x-auto"
                        style={{ background: "hsl(var(--muted))", color: "hsl(var(--foreground))" }}>
                        {JSON.stringify(alert.details, null, 2)}
                      </pre>
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
