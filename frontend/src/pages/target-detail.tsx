import { useParams, Link, useLocation } from "wouter";
import { useGetTarget } from "@/api-client";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Globe, ArrowLeft, ShieldAlert, Bot, Loader2 } from "lucide-react";
import { format } from "date-fns";
import { useState } from "react";

export default function TargetDetail() {
  const params = useParams();
  const [, setLocation] = useLocation();
  const targetId = params.id as string;
  const [isRunningPentest, setRunningPentest] = useState(false);

  const { data: target, isLoading } = useGetTarget(targetId, {
    query: { enabled: !!targetId }
  });

  async function runAutonomousPentest() {
    setRunningPentest(true);
    try {
      const response = await fetch(`/api/ai/autonomous-pentest/${targetId}`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
      });
      const reader = response.body?.getReader();
      if (!reader) return;
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          const data = JSON.parse(line.slice(6));
          console.log("[Pentest]", data.type, data);
        }
      }
    } catch (e) {
      console.error("Pentest failed", e);
    } finally {
      setRunningPentest(false);
    }
  }

  if (isLoading) {
    return <div className="p-8 text-center text-muted-foreground">Loading target...</div>;
  }

  if (!target) {
    return <div className="p-8 text-center text-destructive">Target not found</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center space-x-4">
        <Button variant="outline" size="icon" onClick={() => setLocation('/targets')}>
          <ArrowLeft className="w-4 h-4" />
        </Button>
        <div>
          <h1 className="text-3xl font-bold tracking-tight font-mono">{target.domain}</h1>
          <p className="text-muted-foreground">{target.url}</p>
        </div>
        <div className="ml-auto flex items-center gap-3">
          <Button
            onClick={runAutonomousPentest}
            disabled={isRunningPentest}
            className="bg-purple-600 hover:bg-purple-700 text-white gap-2"
          >
            {isRunningPentest
              ? <><Loader2 className="w-4 h-4 animate-spin" />Pentesting...</>
              : <><Bot className="w-4 h-4" />AI Autonomous Pentest</>}
          </Button>
          <Badge variant="outline" className={`capitalize ${
            target.status === 'active' ? 'bg-green-500/10 text-green-500 border-green-500/20' :
            'bg-muted text-muted-foreground'
          }`}>
            {target.status}
          </Badge>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground font-medium">Overall Risk Score</CardTitle>
          </CardHeader>
          <CardContent>
            <div className={`text-3xl font-bold ${
              target.risk_score > 80 ? 'text-[hsl(var(--critical))]' :
              target.risk_score > 60 ? 'text-[hsl(var(--high))]' :
              target.risk_score > 30 ? 'text-[hsl(var(--medium))]' :
              'text-[hsl(var(--low))]'
            }`}>
              {target.risk_score}/100
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground font-medium">Total Scans</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{target.total_scans}</div>
            <p className="text-xs text-muted-foreground mt-1">
              Last: {target.last_scanned ? format(new Date(target.last_scanned), "MMM d, yyyy") : 'Never'}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm text-muted-foreground font-medium">Findings</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-2">
              <div className="text-3xl font-bold text-[hsl(var(--critical))]">{target.critical_findings}</div>
              <span className="text-sm text-muted-foreground mb-1">Crit</span>
              <div className="text-3xl font-bold text-[hsl(var(--high))] ml-2">{target.high_findings}</div>
              <span className="text-sm text-muted-foreground mb-1">High</span>
            </div>
            <p className="text-xs text-muted-foreground mt-1">{target.total_findings} total findings</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Tags</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2">
            {target.tags && target.tags.length > 0 ? (
              target.tags.map(tag => (
                <Badge key={tag} variant="secondary">{tag}</Badge>
              ))
            ) : (
              <span className="text-muted-foreground text-sm">No tags assigned.</span>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
