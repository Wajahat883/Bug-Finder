import { useState } from "react";
import { useParams, useLocation } from "wouter";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ArrowLeft, Plus, Trash2, ShieldAlert, Target } from "lucide-react";
import { format } from "date-fns";
import { useToast } from "@/hooks/use-toast";

interface Finding {
  id: string; title: string; severity: string; category: string;
  endpoint: string; validation_status: string; created_at: string;
}
interface EngagementDetail {
  id: string; name: string; description: string | null; status: string;
  start_date: string | null; end_date: string | null; scope_targets: string[];
  team_members: Array<{ user_id: string; username: string; role: string }>;
  rules_of_engagement: string | null; scan_count: number;
}
interface Summary {
  total_scans: number; total_findings: number; findings_by_severity: Record<string, number>;
  average_risk_score: number; target_count: number;
}

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-400/20 text-blue-400 border-blue-400/30",
  info: "bg-muted text-muted-foreground border-border",
};

export default function EngagementDetail() {
  const { id } = useParams<{ id: string }>();
  const [, navigate] = useLocation();
  const { toast } = useToast();
  const qc = useQueryClient();
  const [newTargetId, setNewTargetId] = useState("");

  const { data: engagement, isLoading } = useQuery<EngagementDetail>({
    queryKey: ["engagement", id],
    queryFn: () => fetch(`/api/engagements/${id}`, { credentials: "include" }).then((r) => r.json()),
  });
  const { data: findings } = useQuery<Finding[]>({
    queryKey: ["engagement-findings", id],
    queryFn: () => fetch(`/api/engagements/${id}/findings`, { credentials: "include" }).then((r) => r.json()),
    enabled: !!id,
  });
  const { data: summary } = useQuery<Summary>({
    queryKey: ["engagement-summary", id],
    queryFn: () => fetch(`/api/engagements/${id}/summary`, { credentials: "include" }).then((r) => r.json()),
    enabled: !!id,
  });

  const addTargetMut = useMutation({
    mutationFn: (target_id: string) =>
      fetch(`/api/engagements/${id}/targets`, {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_id }),
      }).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["engagement", id] });
      qc.invalidateQueries({ queryKey: ["engagement-findings", id] });
      qc.invalidateQueries({ queryKey: ["engagement-summary", id] });
      setNewTargetId("");
      toast({ title: "Target added to scope" });
    },
  });

  const removeTargetMut = useMutation({
    mutationFn: (targetId: string) =>
      fetch(`/api/engagements/${id}/targets/${targetId}`, { method: "DELETE", credentials: "include" }).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["engagement", id] });
      qc.invalidateQueries({ queryKey: ["engagement-findings", id] });
      qc.invalidateQueries({ queryKey: ["engagement-summary", id] });
      toast({ title: "Target removed from scope" });
    },
  });

  if (isLoading) return <div className="p-8 text-center text-muted-foreground">Loading...</div>;
  if (!engagement) return <div className="p-8 text-center text-muted-foreground">Engagement not found</div>;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="sm" onClick={() => navigate("/engagements")}>
          <ArrowLeft className="w-4 h-4 mr-1" /> Back
        </Button>
        <div>
          <h1 className="text-xl font-bold text-foreground">{engagement.name}</h1>
          <div className="flex items-center gap-2 mt-1">
            <span className={`text-xs font-medium px-2 py-0.5 rounded border uppercase ${
              engagement.status === "active" ? "bg-green-500/20 text-green-400 border-green-500/30" : "bg-muted text-muted-foreground border-border"
            }`}>{engagement.status}</span>
            {engagement.start_date && (
              <span className="text-xs text-muted-foreground">
                {format(new Date(engagement.start_date), "MMM d, yyyy")} →{" "}
                {engagement.end_date ? format(new Date(engagement.end_date), "MMM d, yyyy") : "Ongoing"}
              </span>
            )}
          </div>
        </div>
      </div>

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="findings">Findings ({findings?.length ?? 0})</TabsTrigger>
          <TabsTrigger value="targets">Targets ({engagement.scope_targets.length})</TabsTrigger>
          <TabsTrigger value="team">Team</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4 mt-4">
          {summary && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { label: "Total Scans", value: summary.total_scans },
                { label: "Total Findings", value: summary.total_findings },
                { label: "In-Scope Targets", value: summary.target_count },
                { label: "Avg Risk Score", value: summary.average_risk_score },
              ].map(({ label, value }) => (
                <Card key={label}>
                  <CardContent className="pt-4">
                    <p className="text-xs text-muted-foreground">{label}</p>
                    <p className="text-2xl font-bold text-foreground">{value}</p>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}

          {summary?.findings_by_severity && (
            <Card>
              <CardHeader><CardTitle className="text-sm">Findings by Severity</CardTitle></CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-3">
                  {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
                    <div key={sev} className={`flex items-center gap-2 px-3 py-2 rounded-lg border ${SEV_COLORS[sev]}`}>
                      <span className="text-xs font-semibold uppercase">{sev}</span>
                      <span className="text-lg font-bold">{summary.findings_by_severity[sev] ?? 0}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {engagement.description && (
            <Card>
              <CardHeader><CardTitle className="text-sm">Description</CardTitle></CardHeader>
              <CardContent><p className="text-sm text-foreground">{engagement.description}</p></CardContent>
            </Card>
          )}

          {engagement.rules_of_engagement && (
            <Card>
              <CardHeader><CardTitle className="text-sm">Rules of Engagement</CardTitle></CardHeader>
              <CardContent><pre className="text-xs text-foreground whitespace-pre-wrap font-sans">{engagement.rules_of_engagement}</pre></CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="findings" className="mt-4">
          <div className="space-y-2">
            {!findings || findings.length === 0 ? (
              <Card><CardContent className="py-8 text-center text-muted-foreground">No findings for in-scope targets.</CardContent></Card>
            ) : findings.map((f) => (
              <Card key={f.id} className="cursor-pointer hover:border-primary/50 transition-colors" onClick={() => navigate(`/findings/${f.id}`)}>
                <CardContent className="py-3 flex items-center justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium text-foreground truncate">{f.title}</p>
                    <p className="text-xs text-muted-foreground truncate">{f.endpoint}</p>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border uppercase ${SEV_COLORS[f.severity] ?? ""}`}>{f.severity}</span>
                    <span className="text-xs text-muted-foreground">{format(new Date(f.created_at), "MMM d")}</span>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="targets" className="mt-4 space-y-4">
          <div className="flex gap-2">
            <Input
              value={newTargetId}
              onChange={(e) => setNewTargetId(e.target.value)}
              placeholder="Target ID to add to scope..."
              className="flex-1"
            />
            <Button onClick={() => newTargetId && addTargetMut.mutate(newTargetId)} disabled={!newTargetId || addTargetMut.isPending}>
              <Plus className="w-4 h-4 mr-1" /> Add
            </Button>
          </div>
          {engagement.scope_targets.length === 0 ? (
            <Card><CardContent className="py-8 text-center text-muted-foreground">No targets in scope yet.</CardContent></Card>
          ) : (
            <div className="space-y-2">
              {engagement.scope_targets.map((tid) => (
                <Card key={tid}>
                  <CardContent className="py-3 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Target className="w-4 h-4 text-muted-foreground" />
                      <span className="text-sm font-mono text-foreground">{tid}</span>
                    </div>
                    <Button variant="ghost" size="sm" onClick={() => removeTargetMut.mutate(tid)}>
                      <Trash2 className="w-4 h-4 text-red-400" />
                    </Button>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="team" className="mt-4">
          {engagement.team_members.length === 0 ? (
            <Card><CardContent className="py-8 text-center text-muted-foreground">No team members assigned.</CardContent></Card>
          ) : (
            <div className="space-y-2">
              {engagement.team_members.map((m, i) => (
                <Card key={i}>
                  <CardContent className="py-3 flex items-center justify-between">
                    <span className="text-sm text-foreground">{(m as Record<string, string>).username}</span>
                    <Badge variant="secondary">{(m as Record<string, string>).role}</Badge>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
