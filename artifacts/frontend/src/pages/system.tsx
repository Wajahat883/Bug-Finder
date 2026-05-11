import { useHealthCheck } from "@workspace/api-client-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Server, Activity, Database, ShieldCheck, Clock, Zap } from "lucide-react";
import { format } from "date-fns";

export default function System() {
  const { data: raw, isLoading } = useHealthCheck({
    query: { refetchInterval: 10000 },
  });

  const health = raw as any;

  const uptimeSecs: number = health?.uptime ?? 0;
  const uptimeH = Math.floor(uptimeSecs / 3600);
  const uptimeM = Math.floor((uptimeSecs % 3600) / 60);
  const timestamp: string = health?.timestamp ?? new Date().toISOString();
  const components = health?.components ?? {};
  const scannerEngines: number = components.scanner_engines ?? 0;
  const dbStatus: string = components.database ?? "unknown";
  const queueStatus: string = components.queue ?? "unknown";
  const overallStatus: string = health?.status ?? "unknown";

  function statusBadgeClass(s: string) {
    return s === "healthy"
      ? "bg-green-500/10 text-green-500 border-green-500/20"
      : "bg-destructive/10 text-destructive border-destructive/20";
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">System Status</h1>
        <p className="text-muted-foreground">Monitor Bug Bounty Pro infrastructure health and metrics.</p>
      </div>

      {isLoading ? (
        <div className="p-8 text-center text-muted-foreground bg-muted/20 rounded-lg border border-border">
          Loading system metrics...
        </div>
      ) : health ? (
        <>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Overall Status</CardTitle>
                <ShieldCheck className={`h-4 w-4 ${overallStatus === "healthy" ? "text-green-500" : "text-destructive"}`} />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold capitalize">{overallStatus}</div>
                <p className="text-xs text-muted-foreground mt-1">Engine nodes are operational</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Uptime</CardTitle>
                <Clock className="h-4 w-4 text-blue-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{uptimeH}h {uptimeM}m</div>
                <p className="text-xs text-muted-foreground mt-1">Since last restart</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Scanner Engines</CardTitle>
                <Zap className="h-4 w-4 text-yellow-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{scannerEngines}</div>
                <p className="text-xs text-muted-foreground mt-1">Available engines online</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Current Time</CardTitle>
                <Activity className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-lg font-bold">{format(new Date(timestamp), "HH:mm:ss")}</div>
                <p className="text-xs text-muted-foreground mt-1">{format(new Date(timestamp), "MMM d, yyyy")}</p>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Component Health</CardTitle>
              <CardDescription>Status of individual platform services</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 border border-border rounded-md bg-muted/20">
                  <div className="flex items-center space-x-4">
                    <Database className="w-6 h-6 text-primary" />
                    <div>
                      <p className="text-sm font-medium leading-none">Primary Database</p>
                      <p className="text-sm text-muted-foreground mt-1">Findings and metadata storage</p>
                    </div>
                  </div>
                  <Badge variant="outline" className={`capitalize ${statusBadgeClass(dbStatus)}`}>
                    {dbStatus}
                  </Badge>
                </div>

                <div className="flex items-center justify-between p-4 border border-border rounded-md bg-muted/20">
                  <div className="flex items-center space-x-4">
                    <Activity className="w-6 h-6 text-primary" />
                    <div>
                      <p className="text-sm font-medium leading-none">Job Queue</p>
                      <p className="text-sm text-muted-foreground mt-1">Scan task distribution and management</p>
                    </div>
                  </div>
                  <Badge variant="outline" className={`capitalize ${statusBadgeClass(queueStatus)}`}>
                    {queueStatus}
                  </Badge>
                </div>

                <div className="flex items-center justify-between p-4 border border-border rounded-md bg-muted/20">
                  <div className="flex items-center space-x-4">
                    <Server className="w-6 h-6 text-primary" />
                    <div>
                      <p className="text-sm font-medium leading-none">API Server</p>
                      <p className="text-sm text-muted-foreground mt-1">REST endpoints and webhooks</p>
                    </div>
                  </div>
                  <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500/20 capitalize">
                    Healthy
                  </Badge>
                </div>
              </div>
            </CardContent>
          </Card>
        </>
      ) : (
        <div className="p-8 text-center text-destructive bg-destructive/10 rounded-lg border border-destructive/20">
          Failed to load system metrics
        </div>
      )}
    </div>
  );
}
