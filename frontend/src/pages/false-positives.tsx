import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  CheckCircle2, XCircle, Clock, AlertTriangle, ShieldOff,
  ExternalLink, Loader2, RefreshCw, Filter, User,
} from "lucide-react";
import { format } from "date-fns";
import { useToast } from "@/hooks/use-toast";

interface FPFinding {
  _id: string;
  title: string;
  severity: string;
  endpoint: string;
  scan_id: string;
  triage_status: string;
  fp_reason: string;
  fp_evidence: string;
  fp_marked_by: string;
  fp_marked_at: string;
  fp_reviewer_id?: string;
  fp_reviewed_at?: string;
  fp_expiry_date?: string;
  suppressed_until?: string;
  ai_triage_assessment?: { fp_probability: number; reasoning: string };
}

const REASON_LABELS: Record<string, string> = {
  test_environment: "Test Environment",
  accepted_risk: "Accepted Risk",
  compensating_control: "Compensating Control",
  not_applicable: "Not Applicable",
  duplicate: "Duplicate",
  other: "Other",
};

function SeverityPill({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    info: "bg-slate-500/20 text-slate-400 border-slate-500/30",
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border uppercase ${map[severity?.toLowerCase()] ?? map.info}`}>
      {severity}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { label: string; cls: string }> = {
    pending_review: { label: "Pending Review", cls: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" },
    confirmed_fp: { label: "Confirmed FP", cls: "bg-green-500/20 text-green-400 border-green-500/30" },
    rejected_fp: { label: "Rejected", cls: "bg-red-500/20 text-red-400 border-red-500/30" },
    suppressed: { label: "Suppressed", cls: "bg-purple-500/20 text-purple-400 border-purple-500/30" },
  };
  const s = map[status] ?? { label: status, cls: "bg-slate-500/20 text-slate-400 border-slate-500/30" };
  return <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${s.cls}`}>{s.label}</span>;
}

function FPCard({ finding, onAction }: { finding: FPFinding; onAction: () => void }) {
  const { toast } = useToast();
  const qc = useQueryClient();

  const reviewMutation = useMutation({
    mutationFn: async ({ action }: { action: "approve" | "reject" }) => {
      const res = await fetch(`/api/findings/${finding._id}/triage/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision: action, notes: action === "approve" ? "Confirmed false positive" : "Finding is valid" }),
      });
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    },
    onSuccess: (_, { action }) => {
      toast({ title: action === "approve" ? "FP Confirmed" : "FP Rejected", description: `Finding has been ${action === "approve" ? "confirmed as false positive" : "rejected — marked as real finding"}.` });
      qc.invalidateQueries({ queryKey: ["false-positives"] });
      onAction();
    },
    onError: (e: Error) => toast({ title: "Action failed", description: e.message, variant: "destructive" }),
  });

  const prob = finding.ai_triage_assessment?.fp_probability;

  return (
    <Card className="border-border/50 hover:border-border transition-colors">
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <SeverityPill severity={finding.severity} />
              <StatusBadge status={finding.triage_status} />
              {prob !== undefined && (
                <span className={`text-xs px-2 py-0.5 rounded-full border ${prob >= 70 ? "bg-green-500/20 text-green-400 border-green-500/30" : prob >= 40 ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" : "bg-red-500/20 text-red-400 border-red-500/30"}`}>
                  AI: {prob}% FP
                </span>
              )}
            </div>
            <Link href={`/findings/${finding._id}`}>
              <a className="font-medium hover:text-primary transition-colors line-clamp-1">{finding.title}</a>
            </Link>
            <p className="text-xs text-muted-foreground mt-0.5 font-mono truncate">{finding.endpoint}</p>
          </div>
          {finding.triage_status === "pending_review" && (
            <div className="flex gap-2 shrink-0">
              <Button size="sm" variant="outline"
                className="border-green-500/50 text-green-400 hover:bg-green-500/10"
                disabled={reviewMutation.isPending}
                onClick={() => reviewMutation.mutate({ action: "approve" })}>
                {reviewMutation.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <CheckCircle2 className="w-3 h-3" />}
                <span className="ml-1">Approve</span>
              </Button>
              <Button size="sm" variant="outline"
                className="border-red-500/50 text-red-400 hover:bg-red-500/10"
                disabled={reviewMutation.isPending}
                onClick={() => reviewMutation.mutate({ action: "reject" })}>
                {reviewMutation.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <XCircle className="w-3 h-3" />}
                <span className="ml-1">Reject</span>
              </Button>
            </div>
          )}
        </div>

        <div className="mt-3 grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          <div>
            <p className="text-muted-foreground">Reason</p>
            <p className="font-medium">{REASON_LABELS[finding.fp_reason] ?? finding.fp_reason ?? "—"}</p>
          </div>
          <div>
            <p className="text-muted-foreground">Marked By</p>
            <p className="font-medium flex items-center gap-1"><User className="w-3 h-3" />{finding.fp_marked_by ?? "—"}</p>
          </div>
          <div>
            <p className="text-muted-foreground">Marked At</p>
            <p className="font-medium">{finding.fp_marked_at ? format(new Date(finding.fp_marked_at), "MMM d, HH:mm") : "—"}</p>
          </div>
          {finding.fp_expiry_date && (
            <div>
              <p className="text-muted-foreground">Expires</p>
              <p className="font-medium text-yellow-400">{format(new Date(finding.fp_expiry_date), "MMM d, yyyy")}</p>
            </div>
          )}
        </div>

        {finding.fp_evidence && (
          <div className="mt-2 p-2 rounded bg-muted/50 text-xs text-muted-foreground">
            <span className="font-medium text-foreground">Evidence: </span>{finding.fp_evidence}
          </div>
        )}

        {finding.ai_triage_assessment?.reasoning && (
          <div className="mt-2 p-2 rounded bg-blue-500/10 border border-blue-500/20 text-xs text-blue-300">
            <span className="font-medium">AI Assessment: </span>{finding.ai_triage_assessment.reasoning}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function SkeletonCard() {
  return (
    <Card className="border-border/50">
      <CardContent className="p-4 space-y-3">
        <div className="flex gap-2">
          <div className="h-5 w-16 rounded-full bg-muted animate-pulse" />
          <div className="h-5 w-24 rounded-full bg-muted animate-pulse" />
        </div>
        <div className="h-4 w-3/4 rounded bg-muted animate-pulse" />
        <div className="h-3 w-1/2 rounded bg-muted animate-pulse" />
      </CardContent>
    </Card>
  );
}

export default function FalsePositivesPage() {
  const [tab, setTab] = useState("pending_review");
  const qc = useQueryClient();

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["false-positives", tab],
    queryFn: async () => {
      const apiStatus = tab === "confirmed_fp" ? "approved" : tab === "rejected_fp" ? "all" : tab;
      const res = await fetch(`/api/findings/false-positives?status=${apiStatus}&limit=50`);
      if (!res.ok) throw new Error("Failed to load");
      return res.json() as Promise<{ items: FPFinding[]; total: number; page: number }>;
    },
  });

  const findings = data?.items ?? [];
  const total = data?.total ?? 0;

  const tabCounts: Record<string, number | undefined> = {};

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ShieldOff className="w-6 h-6 text-yellow-400" />
            False Positive Review Queue
          </h1>
          <p className="text-muted-foreground text-sm mt-1">Four-eyes review workflow — a second analyst must confirm or reject each FP.</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()}>
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Stats strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Pending Review", value: total, icon: Clock, color: "text-yellow-400" },
          { label: "Confirmed FPs", value: "—", icon: CheckCircle2, color: "text-green-400" },
          { label: "Rejected FPs", value: "—", icon: XCircle, color: "text-red-400" },
          { label: "Suppressed", value: "—", icon: AlertTriangle, color: "text-purple-400" },
        ].map(({ label, value, icon: Icon, color }) => (
          <Card key={label} className="border-border/50">
            <CardContent className="p-4">
              <div className="flex items-center gap-2 text-muted-foreground text-xs mb-1">
                <Icon className={`w-3.5 h-3.5 ${color}`} />
                {label}
              </div>
              <div className="text-2xl font-bold">{value}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Tabs */}
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="bg-muted/50">
          <TabsTrigger value="pending_review" className="gap-2">
            <Clock className="w-3.5 h-3.5" /> Pending Review
          </TabsTrigger>
          <TabsTrigger value="confirmed_fp" className="gap-2">
            <CheckCircle2 className="w-3.5 h-3.5" /> Confirmed FPs
          </TabsTrigger>
          <TabsTrigger value="rejected_fp" className="gap-2">
            <XCircle className="w-3.5 h-3.5" /> Rejected
          </TabsTrigger>
          <TabsTrigger value="suppressed" className="gap-2">
            <AlertTriangle className="w-3.5 h-3.5" /> Suppressed
          </TabsTrigger>
        </TabsList>

        {["pending_review", "confirmed_fp", "rejected_fp", "suppressed"].map((t) => (
          <TabsContent key={t} value={t} className="mt-4 space-y-3">
            {isLoading ? (
              Array.from({ length: 3 }).map((_, i) => <SkeletonCard key={i} />)
            ) : findings.length === 0 ? (
              <Card className="border-border/50">
                <CardContent className="p-12 text-center">
                  <CheckCircle2 className="w-10 h-10 text-green-400 mx-auto mb-3" />
                  <p className="text-muted-foreground">No findings in this queue.</p>
                </CardContent>
              </Card>
            ) : (
              findings.map((f) => (
                <FPCard key={f._id} finding={f} onAction={() => qc.invalidateQueries({ queryKey: ["false-positives"] })} />
              ))
            )}
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );
}
