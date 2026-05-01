import { useState, useEffect } from "react";
import { useParams, Link, useLocation } from "wouter";
import { 
  useGetScanJob, 
  useGetScanJobFindings,
  useGetScanJobAttackSurface
} from "@workspace/api-client-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Download, AlertTriangle, Info, Clock, Activity, FileText, CheckCircle2, XCircle } from "lucide-react";
import { format } from "date-fns";

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

export default function ScanDetail() {
  const params = useParams();
  const [, setLocation] = useLocation();
  const scanId = params.id as string;

  const { data: scan, isLoading: scanLoading } = useGetScanJob(scanId, {
    query: {
      refetchInterval: (query) => {
        const status = query.state.data?.status;
        return (status === 'queued' || status === 'running') ? 3000 : false;
      }
    }
  });

  const { data: findings, isLoading: findingsLoading } = useGetScanJobFindings(scanId);
  const { data: attackSurface } = useGetScanJobAttackSurface(scanId);

  if (scanLoading) {
    return <div className="p-8 flex justify-center text-muted-foreground">Loading scan details...</div>;
  }

  if (!scan) {
    return <div className="p-8 text-center text-destructive">Scan not found</div>;
  }

  const isRunning = scan.status === 'running' || scan.status === 'queued';

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-3 mb-1">
            <h1 className="text-3xl font-bold tracking-tight font-mono">{scan.target_url}</h1>
            <Badge variant="outline" className={`capitalize ${
              scan.status === 'running' ? 'bg-blue-500/10 text-blue-500 border-blue-500/20 animate-pulse' :
              scan.status === 'completed' ? 'bg-green-500/10 text-green-500 border-green-500/20' :
              scan.status === 'failed' ? 'bg-destructive/10 text-destructive border-destructive/20' :
              'bg-muted text-muted-foreground'
            }`}>
              {scan.status}
            </Badge>
          </div>
          <p className="text-muted-foreground flex items-center">
            <Clock className="w-4 h-4 mr-1.5" />
            Started {format(new Date(scan.created_at), "MMM d, yyyy HH:mm")}
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button variant="outline" disabled={isRunning}>
            <Download className="w-4 h-4 mr-2" />
            Export JSON
          </Button>
          <Button variant="outline" disabled={isRunning}>
            <FileText className="w-4 h-4 mr-2" />
            PDF Report
          </Button>
        </div>
      </div>

      {isRunning && (
        <Card className="border-blue-500/20 bg-blue-500/5">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-blue-500">Scan in progress...</span>
              <span className="text-sm font-mono text-blue-500">{scan.progress}%</span>
            </div>
            <Progress value={scan.progress} className="h-2 [&>div]:bg-blue-500" />
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground font-medium">Risk Score</CardTitle>
          </CardHeader>
          <CardContent>
            <div className={`text-3xl font-bold ${
              scan.risk_score > 80 ? 'text-[hsl(var(--critical))]' :
              scan.risk_score > 60 ? 'text-[hsl(var(--high))]' :
              scan.risk_score > 30 ? 'text-[hsl(var(--medium))]' :
              'text-[hsl(var(--low))]'
            }`}>{scan.risk_score}/100</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground font-medium">Critical</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-[hsl(var(--critical))]">{scan.critical_count}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground font-medium">High</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-[hsl(var(--high))]">{scan.high_count}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground font-medium">Medium</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-[hsl(var(--medium))]">{scan.medium_count}</div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="findings" className="w-full">
        <TabsList className="w-full justify-start border-b border-border rounded-none bg-transparent h-auto p-0">
          <TabsTrigger value="findings" className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent px-6 py-3">
            Findings ({scan.findings_count})
          </TabsTrigger>
          <TabsTrigger value="summary" className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent px-6 py-3">
            AI Summary
          </TabsTrigger>
          <TabsTrigger value="surface" className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent px-6 py-3">
            Attack Surface
          </TabsTrigger>
          <TabsTrigger value="config" className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent px-6 py-3">
            Configuration
          </TabsTrigger>
        </TabsList>
        
        <TabsContent value="findings" className="pt-6">
          <Card>
            <div className="rounded-md border-0">
              <table className="w-full text-sm text-left">
                <thead className="text-xs text-muted-foreground uppercase bg-muted/50">
                  <tr>
                    <th className="px-4 py-3">Severity</th>
                    <th className="px-4 py-3">Title</th>
                    <th className="px-4 py-3">Category</th>
                    <th className="px-4 py-3">Endpoint</th>
                    <th className="px-4 py-3 text-right">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {findingsLoading ? (
                    <tr>
                      <td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">Loading findings...</td>
                    </tr>
                  ) : findings?.items.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">
                        {isRunning ? "No findings discovered yet..." : "No vulnerabilities found. System secure."}
                      </td>
                    </tr>
                  ) : (
                    findings?.items.map((finding) => (
                      <tr key={finding.id} className="hover:bg-muted/20 cursor-pointer" onClick={() => setLocation(`/findings/${finding.id}`)}>
                        <td className="px-4 py-3 w-24">
                          <SeverityBadge severity={finding.severity} />
                        </td>
                        <td className="px-4 py-3 font-medium">{finding.title}</td>
                        <td className="px-4 py-3 text-muted-foreground text-xs">{finding.category}</td>
                        <td className="px-4 py-3 font-mono text-xs max-w-[200px] truncate" title={finding.endpoint}>
                          {finding.endpoint}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <Badge variant="outline" className="text-[10px] capitalize">
                            {finding.validation_status.replace('_', ' ')}
                          </Badge>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </Card>
        </TabsContent>
        
        <TabsContent value="summary" className="pt-6">
          <Card>
            <CardHeader>
              <CardTitle>AI Executive Summary</CardTitle>
              <CardDescription>Generated assessment of the target's security posture</CardDescription>
            </CardHeader>
            <CardContent>
              {scan.ai_summary ? (
                <div className="prose prose-sm dark:prose-invert max-w-none">
                  {scan.ai_summary.split('\n\n').map((paragraph, i) => (
                    <p key={i}>{paragraph}</p>
                  ))}
                </div>
              ) : (
                <div className="text-center py-12 text-muted-foreground">
                  {isRunning ? "AI analysis will be generated upon scan completion..." : "AI summary not available for this scan."}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="surface" className="pt-6">
          <Card>
            <CardHeader>
              <CardTitle>Attack Surface Map</CardTitle>
              <CardDescription>Discovered nodes and relationships</CardDescription>
            </CardHeader>
            <CardContent>
              {attackSurface ? (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                    <div className="p-4 bg-muted/50 rounded-md">
                      <div className="text-2xl font-bold">{attackSurface.nodes.filter(n => n.type === 'domain').length}</div>
                      <div className="text-xs text-muted-foreground uppercase">Domains</div>
                    </div>
                    <div className="p-4 bg-muted/50 rounded-md">
                      <div className="text-2xl font-bold">{attackSurface.nodes.filter(n => n.type === 'endpoint').length}</div>
                      <div className="text-xs text-muted-foreground uppercase">Endpoints</div>
                    </div>
                    <div className="p-4 bg-muted/50 rounded-md">
                      <div className="text-2xl font-bold">{attackSurface.nodes.filter(n => n.type === 'parameter').length}</div>
                      <div className="text-xs text-muted-foreground uppercase">Parameters</div>
                    </div>
                    <div className="p-4 bg-muted/50 rounded-md">
                      <div className="text-2xl font-bold">{attackSurface.edges.length}</div>
                      <div className="text-xs text-muted-foreground uppercase">Connections</div>
                    </div>
                  </div>
                  {/* Simplistic representation of attack surface data */}
                  <div className="border border-border rounded-md overflow-hidden">
                    <table className="w-full text-sm">
                      <thead className="bg-muted/50 text-xs uppercase text-muted-foreground">
                        <tr>
                          <th className="px-4 py-2 text-left">Node Type</th>
                          <th className="px-4 py-2 text-left">Identifier</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border">
                        {attackSurface.nodes.slice(0, 20).map(node => (
                          <tr key={node.id}>
                            <td className="px-4 py-2"><Badge variant="outline" className="text-[10px]">{node.type}</Badge></td>
                            <td className="px-4 py-2 font-mono text-xs">{node.label}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {attackSurface.nodes.length > 20 && (
                      <div className="p-2 text-center text-xs text-muted-foreground bg-muted/20 border-t border-border">
                        Showing 20 of {attackSurface.nodes.length} nodes
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="text-center py-12 text-muted-foreground">
                  {isRunning ? "Mapping attack surface..." : "No attack surface data available."}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="config" className="pt-6">
          <Card>
            <CardHeader>
              <CardTitle>Scan Configuration</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="grid grid-cols-1 md:grid-cols-2 gap-x-4 gap-y-6 text-sm">
                <div>
                  <dt className="text-muted-foreground font-medium mb-1">Target URL</dt>
                  <dd className="font-mono">{scan.target_url}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground font-medium mb-1">Profile</dt>
                  <dd className="uppercase tracking-wide">{scan.scan_profile}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground font-medium mb-1">Engines Used</dt>
                  <dd className="flex gap-2">
                    {scan.scanner_engines.map(engine => (
                      <Badge key={engine} variant="secondary" className="capitalize">{engine}</Badge>
                    ))}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground font-medium mb-1">Options</dt>
                  <dd className="space-y-1">
                    <div className="flex items-center">
                      {scan.validation_enabled ? <CheckCircle2 className="w-4 h-4 text-green-500 mr-2" /> : <XCircle className="w-4 h-4 text-muted-foreground mr-2" />}
                      <span>Validation</span>
                    </div>
                    <div className="flex items-center">
                      {scan.fuzzing_enabled ? <CheckCircle2 className="w-4 h-4 text-green-500 mr-2" /> : <XCircle className="w-4 h-4 text-muted-foreground mr-2" />}
                      <span>Active Fuzzing</span>
                    </div>
                    <div className="flex items-center">
                      {scan.bug_bounty_mode ? <CheckCircle2 className="w-4 h-4 text-green-500 mr-2" /> : <XCircle className="w-4 h-4 text-muted-foreground mr-2" />}
                      <span>Bug Bounty Mode</span>
                    </div>
                  </dd>
                </div>
              </dl>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
