import { useEffect } from "react";
import { Link, useLocation } from "wouter";
import { 
  useGetDashboardStats, 
  useGetDashboardActivity,
  useListScanJobs
} from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Activity, ShieldAlert, Target, Play, AlertCircle, AlertTriangle, Info, Plus } from "lucide-react";
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-[hsl(var(--critical))] text-white",
    high: "bg-[hsl(var(--high))] text-white",
    medium: "bg-[hsl(var(--medium))] text-black",
    low: "bg-[hsl(var(--low))] text-black",
    info: "bg-[hsl(var(--info))] text-white",
  };
  
  return (
    <Badge className={`${colors[severity.toLowerCase()]} border-none uppercase text-[10px]`}>
      {severity}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    queued: "bg-muted text-muted-foreground",
    running: "bg-blue-500/20 text-blue-500 border-blue-500/30 animate-pulse",
    completed: "bg-green-500/20 text-green-500 border-green-500/30",
    failed: "bg-destructive/20 text-destructive border-destructive/30",
    cancelled: "bg-muted text-muted-foreground",
  };
  
  return (
    <Badge variant="outline" className={`${colors[status.toLowerCase()]} capitalize`}>
      {status}
    </Badge>
  );
}

export default function Dashboard() {
  const { data: stats, isLoading: statsLoading } = useGetDashboardStats({
    query: { refetchInterval: 10000 }
  });
  
  const { data: activity } = useGetDashboardActivity(undefined, {
    query: { refetchInterval: 10000 }
  });
  
  const { data: recentScans } = useListScanJobs({ page_size: 5 });

  const [, setLocation] = useLocation();

  if (statsLoading) {
    return <div className="p-8 flex justify-center items-center h-full text-muted-foreground">Loading command center...</div>;
  }

  const pieData = [
    { name: 'Critical', value: stats?.critical_findings || 0, color: 'hsl(var(--critical))' },
    { name: 'High', value: stats?.high_findings || 0, color: 'hsl(var(--high))' },
    { name: 'Medium', value: stats?.medium_findings || 0, color: 'hsl(var(--medium))' },
    { name: 'Low', value: stats?.low_findings || 0, color: 'hsl(var(--low))' },
    { name: 'Info', value: stats?.info_findings || 0, color: 'hsl(var(--info))' },
  ].filter(d => d.value > 0);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Command Center</h1>
          <p className="text-muted-foreground">System overview and active security operations.</p>
        </div>
        <Button onClick={() => setLocation('/scans/new')}>
          <Plus className="w-4 h-4 mr-2" />
          New Scan
        </Button>
      </div>

      {/* KPIs */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Scans</CardTitle>
            <Activity className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.active_scans || 0}</div>
            <p className="text-xs text-muted-foreground">
              {stats?.total_scans} total scans historically
            </p>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Vulnerabilities</CardTitle>
            <ShieldAlert className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.total_findings || 0}</div>
            <p className="text-xs text-muted-foreground">
              Across {stats?.total_targets} known targets
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Critical Issues</CardTitle>
            <AlertCircle className="h-4 w-4 text-[hsl(var(--critical))]" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-[hsl(var(--critical))]">{stats?.critical_findings || 0}</div>
            <p className="text-xs text-muted-foreground">
              Requires immediate remediation
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">System Risk Score</CardTitle>
            <Target className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.risk_score || 0}/100</div>
            <p className="text-xs text-muted-foreground">
              Overall security posture
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
        {/* Severity Breakdown */}
        <Card className="col-span-3">
          <CardHeader>
            <CardTitle>Vulnerability Distribution</CardTitle>
            <CardDescription>Findings grouped by severity level</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-[300px] w-full">
              {pieData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieData}
                      innerRadius={60}
                      outerRadius={80}
                      paddingAngle={5}
                      dataKey="value"
                    >
                      {pieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip 
                      contentStyle={{ backgroundColor: 'hsl(var(--card))', borderColor: 'hsl(var(--border))' }}
                      itemStyle={{ color: 'hsl(var(--foreground))' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex items-center justify-center text-muted-foreground text-sm">
                  No findings to display
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Activity Feed */}
        <Card className="col-span-4">
          <CardHeader>
            <CardTitle>Recent Activity</CardTitle>
            <CardDescription>Latest events from the security engines</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {activity?.slice(0, 5).map((event) => (
                <div key={event.id} className="flex items-start space-x-4 border-b border-border/50 pb-4 last:border-0">
                  <div className={`mt-0.5 p-1.5 rounded-full ${
                    event.type === 'scan_completed' ? 'bg-green-500/20 text-green-500' :
                    event.type === 'scan_failed' ? 'bg-destructive/20 text-destructive' :
                    event.type === 'finding_discovered' ? 'bg-orange-500/20 text-orange-500' :
                    'bg-blue-500/20 text-blue-500'
                  }`}>
                    {event.type === 'scan_completed' ? <Target className="w-4 h-4" /> :
                     event.type === 'scan_failed' ? <AlertCircle className="w-4 h-4" /> :
                     event.type === 'finding_discovered' ? <ShieldAlert className="w-4 h-4" /> :
                     <Activity className="w-4 h-4" />}
                  </div>
                  <div className="flex-1 space-y-1">
                    <p className="text-sm font-medium leading-none">{event.message}</p>
                    <p className="text-xs text-muted-foreground">
                      {new Date(event.timestamp).toLocaleString()}
                    </p>
                  </div>
                </div>
              ))}
              {(!activity || activity.length === 0) && (
                <div className="text-center py-4 text-muted-foreground text-sm">No recent activity</div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Recent Scans */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Scan Jobs</CardTitle>
          <CardDescription>Latest vulnerability assessments</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="text-xs text-muted-foreground uppercase bg-muted/50">
                <tr>
                  <th className="px-4 py-3 rounded-tl-md">Target</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Profile</th>
                  <th className="px-4 py-3">Findings</th>
                  <th className="px-4 py-3 rounded-tr-md text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {recentScans?.items.map((scan) => (
                  <tr key={scan.id} className="border-b border-border/50 hover:bg-muted/20">
                    <td className="px-4 py-3 font-mono font-medium">{scan.target_url}</td>
                    <td className="px-4 py-3"><StatusBadge status={scan.status} /></td>
                    <td className="px-4 py-3 uppercase text-xs font-bold tracking-wider text-muted-foreground">{scan.scan_profile}</td>
                    <td className="px-4 py-3">
                      {scan.status === 'completed' && scan.findings_count > 0 ? (
                        <div className="flex gap-1">
                          {scan.critical_count > 0 && <SeverityBadge severity="critical" />}
                          {scan.high_count > 0 && <SeverityBadge severity="high" />}
                          {scan.critical_count === 0 && scan.high_count === 0 && <Badge variant="outline">{scan.findings_count} total</Badge>}
                        </div>
                      ) : (
                        <span className="text-muted-foreground">-</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <Button variant="ghost" size="sm" onClick={() => setLocation(`/scans/${scan.id}`)}>
                        View Details
                      </Button>
                    </td>
                  </tr>
                ))}
                {(!recentScans?.items || recentScans.items.length === 0) && (
                  <tr>
                    <td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">
                      No scan jobs found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
