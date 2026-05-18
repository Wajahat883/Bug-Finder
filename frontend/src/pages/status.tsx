import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { CheckCircle2, XCircle, AlertTriangle, RefreshCw, Activity } from "lucide-react";
import { format } from "date-fns";

interface ComponentStatus {
  status: string;
  latency_ms?: number;
  error?: string;
  active_scans?: number;
}

interface StatusData {
  status: string;
  version: string;
  uptime_seconds: number;
  timestamp: string;
  components: Record<string, ComponentStatus>;
  total_latency_ms: number;
}

function StatusDot({ status }: { status: string }) {
  if (status === "healthy" || status === "operational") return <span className="w-2.5 h-2.5 rounded-full bg-green-500 inline-block" />;
  if (status === "degraded") return <span className="w-2.5 h-2.5 rounded-full bg-yellow-500 inline-block animate-pulse" />;
  return <span className="w-2.5 h-2.5 rounded-full bg-red-500 inline-block animate-pulse" />;
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    operational: "bg-green-500/15 text-green-400 border-green-500/30",
    healthy: "bg-green-500/15 text-green-400 border-green-500/30",
    degraded: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    partial_outage: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    outage: "bg-red-500/15 text-red-400 border-red-500/30",
    unknown: "bg-muted/50 text-muted-foreground border-border",
  };
  return (
    <Badge className={`capitalize border text-xs ${map[status] ?? map["unknown"]}`}>
      {status.replace(/_/g, " ")}
    </Badge>
  );
}

function formatUptime(seconds: number) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${d}d ${h}h ${m}m`;
}

const COMPONENT_NAMES: Record<string, string> = {
  mongodb: "Database (MongoDB)",
  redis: "Cache (Redis)",
  scanner: "Scan Engine",
};

export default function StatusPage() {
  const { data, isLoading, dataUpdatedAt, refetch } = useQuery<StatusData>({
    queryKey: ["/api/status"],
    queryFn: () => fetch("/api/status").then(r => r.json()),
    refetchInterval: 30000,
  });

  const { data: incidents = [] } = useQuery<Array<Record<string, unknown>>>({
    queryKey: ["/api/status/incidents"],
    queryFn: () => fetch("/api/status/incidents", { credentials: "include" }).then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }),
  });

  const { data: scannerHealth } = useQuery({
    queryKey: ["/api/scanner/health"],
    queryFn: () => fetch("/api/scanner/health", { credentials: "include" }).then(r => r.json()),
    refetchInterval: 60000,
  });

  const overallOk = data?.status === "operational";
  const overallDegraded = data?.status === "degraded";

  return (
    <div className="max-w-3xl mx-auto space-y-6 py-8 px-4">
      <div className="text-center space-y-2">
        <h1 className="text-3xl font-bold flex items-center justify-center gap-2">
          <Activity className="w-8 h-8" />
          System Status
        </h1>
        <p className="text-muted-foreground">Real-time health of Bug Finder Pro services</p>
      </div>

      <Card className={`border-2 ${overallOk ? "border-green-500/40 bg-green-500/5" : overallDegraded ? "border-yellow-500/40 bg-yellow-500/5" : "border-red-500/40 bg-red-500/5"}`}>
        <CardContent className="p-6 flex items-center justify-between">
          <div className="flex items-center gap-3">
            {overallOk
              ? <CheckCircle2 className="w-8 h-8 text-green-500" />
              : overallDegraded
              ? <AlertTriangle className="w-8 h-8 text-yellow-500" />
              : <XCircle className="w-8 h-8 text-red-500" />}
            <div>
              <div className="text-xl font-bold capitalize">{(data?.status ?? "checking...").replace(/_/g, " ")}</div>
              <div className="text-sm text-muted-foreground">
                {data ? `Uptime: ${formatUptime(data.uptime_seconds)} · v${data.version}` : "Loading..."}
              </div>
            </div>
          </div>
          <div className="text-right">
            <button onClick={() => refetch()} className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1 ml-auto">
              <RefreshCw className="w-3 h-3" /> Refresh
            </button>
            {dataUpdatedAt > 0 && (
              <div className="text-xs text-muted-foreground mt-1">Updated {format(new Date(dataUpdatedAt), "HH:mm:ss")}</div>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3"><CardTitle className="text-base">Components</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          {isLoading ? (
            <div className="text-center py-8 text-muted-foreground">Checking components...</div>
          ) : data?.components ? (
            Object.entries(data.components).map(([key, comp]) => (
              <div key={key} className="flex items-center justify-between p-3 rounded-lg border border-border">
                <div className="flex items-center gap-3">
                  <StatusDot status={comp.status} />
                  <div>
                    <div className="font-medium text-sm">{COMPONENT_NAMES[key] ?? key}</div>
                    {comp.error && <div className="text-xs text-red-400">{comp.error}</div>}
                    {comp.active_scans !== undefined && (
                      <div className="text-xs text-muted-foreground">{comp.active_scans} active scan(s)</div>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  {comp.latency_ms !== undefined && (
                    <span className="text-xs text-muted-foreground font-mono">{comp.latency_ms}ms</span>
                  )}
                  <StatusBadge status={comp.status} />
                </div>
              </div>
            ))
          ) : (
            <div className="text-center py-8 text-muted-foreground">No component data</div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3"><CardTitle className="text-base">Scanner Engine</CardTitle></CardHeader>
        <CardContent className="space-y-2">
          {[
            { label: "Nuclei Binary", ok: scannerHealth?.nuclei_binary, detail: scannerHealth?.nuclei_version ? `v${scannerHealth.nuclei_version}` : "Not installed" },
            { label: "Docker", ok: scannerHealth?.docker, detail: scannerHealth?.docker ? "Available" : "Not available" },
            { label: "Active Mode", ok: scannerHealth?.mode !== "simulation", detail: scannerHealth?.mode === "binary" ? "Real binary (full scan)" : scannerHealth?.mode === "docker" ? "Docker mode" : "⚠ Simulation mode — install Nuclei for real scans" },
          ].map(item => (
            <div key={item.label} className="flex items-center justify-between p-2 rounded border border-border">
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${item.ok ? "bg-green-500" : "bg-red-500"}`} />
                <span className="text-sm font-medium">{item.label}</span>
              </div>
              <span className={`text-xs ${item.ok ? "text-muted-foreground" : "text-red-400"}`}>{item.detail}</span>
            </div>
          ))}
        </CardContent>
      </Card>

      {data && (
        <Card>
          <CardHeader className="pb-3"><CardTitle className="text-base">Performance</CardTitle></CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-4 text-center">
              <div>
                <div className="text-2xl font-bold font-mono text-primary">{data.total_latency_ms}ms</div>
                <div className="text-xs text-muted-foreground">Health Check Latency</div>
              </div>
              <div>
                <div className="text-2xl font-bold font-mono">{formatUptime(data.uptime_seconds)}</div>
                <div className="text-xs text-muted-foreground">Uptime</div>
              </div>
              <div>
                <div className="text-2xl font-bold font-mono text-green-400">v{data.version}</div>
                <div className="text-xs text-muted-foreground">Version</div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader className="pb-3"><CardTitle className="text-base">Recent Incidents</CardTitle></CardHeader>
        <CardContent>
          {incidents.length === 0 ? (
            <div className="flex items-center gap-2 py-4 text-green-400 text-sm">
              <CheckCircle2 className="w-4 h-4" />
              No incidents reported in the last 30 days
            </div>
          ) : (
            <div className="space-y-2">
              {incidents.map(i => (
                <div key={String(i["_id"])} className="p-3 rounded-lg border border-border">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-sm">{String(i["title"] ?? "")}</span>
                    <Badge variant="outline" className="text-xs">{String(i["status"] ?? "")}</Badge>
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">
                    {i["created_at"] ? format(new Date(String(i["created_at"])), "MMM d, HH:mm") : ""}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <div className="text-center text-xs text-muted-foreground">
        Auto-refreshes every 30s · Last checked: {data?.timestamp ? format(new Date(data.timestamp), "HH:mm:ss") : "—"}
      </div>
    </div>
  );
}
