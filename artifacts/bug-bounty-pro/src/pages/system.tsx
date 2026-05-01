import { useHealthCheck } from "@workspace/api-client-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Server, Activity, Database, ShieldCheck, Clock, Zap } from "lucide-react";
import { format } from "date-fns";

export default function System() {
  const { data: health, isLoading } = useHealthCheck({
    query: { refetchInterval: 10000 } // poll every 10s
  });

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
                <ShieldCheck className={`h-4 w-4 ${health.status === 'healthy' ? 'text-green-500' : 'text-destructive'}`} />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold capitalize">{health.status}</div>
                <p className="text-xs text-muted-foreground mt-1">
                  Engine nodes are operational
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Uptime</CardTitle>
                <Clock className="h-4 w-4 text-blue-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{Math.floor(health.uptime / 3600)}h {Math.floor((health.uptime % 3600) / 60)}m</div>
                <p className="text-xs text-muted-foreground mt-1">
                  Since last restart
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Scanner Engines</CardTitle>
                <Zap className="h-4 w-4 text-yellow-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{health.components.scanner_engines}</div>
                <p className="text-xs text-muted-foreground mt-1">
                  Available engines online
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Current Time</CardTitle>
                <Activity className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-lg font-bold">{format(new Date(health.timestamp), "HH:mm:ss")}</div>
                <p className="text-xs text-muted-foreground mt-1">
                  {format(new Date(health.timestamp), "MMM d, yyyy")}
                </p>
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
                  <Badge variant="outline" className={`capitalize ${health.components.database === 'healthy' ? 'bg-green-500/10 text-green-500 border-green-500/20' : 'bg-destructive/10 text-destructive border-destructive/20'}`}>
                    {health.components.database}
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
                  <Badge variant="outline" className={`capitalize ${health.components.queue === 'healthy' ? 'bg-green-500/10 text-green-500 border-green-500/20' : 'bg-destructive/10 text-destructive border-destructive/20'}`}>
                    {health.components.queue}
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
