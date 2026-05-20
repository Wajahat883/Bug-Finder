import { useState, useEffect, useCallback, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "wouter";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  CheckCircle2, XCircle, Clock, AlertTriangle, ShieldOff,
  Loader2, RefreshCw, User, ChevronDown, ChevronUp,
  Search, SlidersHorizontal, Keyboard, Shield, Brain,
  CalendarClock, ExternalLink,
} from "lucide-react";
import { format, formatDistanceToNow, differenceInDays } from "date-fns";
import { useToast } from "@/hooks/use-toast";

// ─── Types ────────────────────────────────────────────────────────────────────

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
  fp_reviewer_name?: string;
  fp_reviewer_note?: string;
  fp_reviewed_at?: string;
  fp_expiry_date?: string;
  suppressed_until?: string;
  ai_triage_assessment?: { fp_probability: number; reasoning: string };
}

// ─── Constants ────────────────────────────────────────────────────────────────

const REASON_LABELS: Record<string, string> = {
  test_environment: "Test Environment",
  accepted_risk: "Accepted Risk",
  compensating_control: "Compensating Control",
  not_applicable: "Not Applicable",
  duplicate: "Duplicate",
  other: "Other",
};

const EXPIRY_OPTIONS = [
  { label: "No expiry", value: "" },
  { label: "30 days", value: "30" },
  { label: "90 days", value: "90" },
  { label: "1 year", value: "365" },
];

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const TABS = [
  { value: "pending_review", label: "Pending Review", icon: Clock, color: "text-yellow-400", apiStatus: "pending_review" },
  { value: "confirmed_fp",   label: "Confirmed FPs",  icon: CheckCircle2, color: "text-green-400", apiStatus: "confirmed_fp" },
  { value: "rejected_fp",    label: "Rejected",       icon: XCircle, color: "text-red-400", apiStatus: "rejected_fp" },
  { value: "suppressed",     label: "Suppressed",     icon: Shield, color: "text-purple-400", apiStatus: "suppressed" },
] as const;

// ─── Sub-components ───────────────────────────────────────────────────────────

function SeverityPill({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high:     "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium:   "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    low:      "bg-blue-500/20 text-blue-400 border-blue-500/30",
    info:     "bg-slate-500/20 text-slate-400 border-slate-500/30",
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold border uppercase tracking-wide ${map[severity?.toLowerCase()] ?? map.info}`}>
      {severity}
    </span>
  );
}

function AgingBadge({ markedAt }: { markedAt: string }) {
  const days = differenceInDays(new Date(), new Date(markedAt));
  const cls = days > 7
    ? "bg-red-500/20 text-red-400 border-red-500/30"
    : days > 3
    ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
    : "bg-muted/50 text-muted-foreground border-border";
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs border ${cls}`} title={`Marked ${format(new Date(markedAt), "MMM d, HH:mm")}`}>
      <CalendarClock className="w-3 h-3" />
      {days === 0 ? "Today" : `${days}d`}
    </span>
  );
}

function AiBar({ prob }: { prob: number }) {
  const color = prob >= 70 ? "#22c55e" : prob >= 40 ? "#eab308" : "#ef4444";
  const label = prob >= 70 ? "Likely FP" : prob >= 40 ? "Uncertain" : "Likely Real";
  return (
    <div className="flex items-center gap-2 mt-2">
      <Brain className="w-3.5 h-3.5 shrink-0" style={{ color }} />
      <div className="flex-1 h-1.5 rounded-full bg-muted overflow-hidden">
        <div className="h-full rounded-full transition-all" style={{ width: `${prob}%`, background: color }} />
      </div>
      <span className="text-xs font-mono shrink-0" style={{ color }}>{prob}% — {label}</span>
    </div>
  );
}

function SkeletonCard() {
  return (
    <Card className="border-border/50">
      <CardContent className="p-4 space-y-3">
        <div className="flex gap-2">
          <div className="h-5 w-16 rounded-full bg-muted animate-pulse" />
          <div className="h-5 w-24 rounded-full bg-muted animate-pulse" />
          <div className="h-5 w-12 rounded-full bg-muted animate-pulse" />
        </div>
        <div className="h-4 w-3/4 rounded bg-muted animate-pulse" />
        <div className="h-3 w-1/2 rounded bg-muted animate-pulse" />
        <div className="h-1.5 w-full rounded bg-muted animate-pulse" />
      </CardContent>
    </Card>
  );
}

function EmptyState({ tab }: { tab: string }) {
  const states: Record<string, { icon: React.ReactNode; title: string; desc: string }> = {
    pending_review: {
      icon: <CheckCircle2 className="w-12 h-12 text-green-400" />,
      title: "Queue is clear",
      desc: "All false positives have been reviewed. Great work.",
    },
    confirmed_fp: {
      icon: <ShieldOff className="w-12 h-12 text-slate-500" />,
      title: "No confirmed false positives",
      desc: "Confirmed FPs will appear here once a reviewer approves them.",
    },
    rejected_fp: {
      icon: <AlertTriangle className="w-12 h-12 text-orange-400" />,
      title: "No rejected FPs",
      desc: "Rejected FPs means all reviewed findings were real vulnerabilities.",
    },
    suppressed: {
      icon: <Clock className="w-12 h-12 text-purple-400" />,
      title: "No suppressed findings",
      desc: "Findings suppressed with an expiry date appear here.",
    },
  };
  const s = states[tab] ?? states.pending_review;
  return (
    <Card className="border-border/50 border-dashed">
      <CardContent className="p-14 flex flex-col items-center text-center gap-3">
        {s.icon}
        <p className="font-semibold text-foreground">{s.title}</p>
        <p className="text-sm text-muted-foreground max-w-xs">{s.desc}</p>
      </CardContent>
    </Card>
  );
}

// ─── FP Card ─────────────────────────────────────────────────────────────────

interface FPCardProps {
  finding: FPFinding;
  focused: boolean;
  selected: boolean;
  onSelect: (id: string, checked: boolean) => void;
  onAction: () => void;
  tabRef?: (el: HTMLDivElement | null) => void;
}

function FPCard({ finding, focused, selected, onSelect, onAction, tabRef }: FPCardProps) {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [expanded, setExpanded] = useState(false);
  const [reviewOpen, setReviewOpen] = useState<"approve" | "reject" | null>(null);
  const [reviewNote, setReviewNote] = useState("");
  const [reviewExpiry, setReviewExpiry] = useState("");

  const reviewMutation = useMutation({
    mutationFn: async ({ action, note, expiry }: { action: "approve" | "reject"; note: string; expiry: string }) => {
      const body: Record<string, unknown> = {
        decision: action,
        notes: note.trim() || (action === "approve" ? "Confirmed false positive" : "Finding is valid"),
      };
      if (expiry) {
        const days = parseInt(expiry);
        body.fp_expiry_date = new Date(Date.now() + days * 86400_000).toISOString();
      }
      const res = await fetch(`/api/findings/${finding._id}/triage/review`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(await res.text());
      return res.json();
    },
    onSuccess: (_, { action }) => {
      toast({
        title: action === "approve" ? "✓ FP Confirmed" : "✗ FP Rejected",
        description: action === "approve"
          ? "Finding confirmed as false positive."
          : "Finding rejected — marked as real vulnerability.",
      });
      qc.invalidateQueries({ queryKey: ["false-positives"] });
      setReviewOpen(null);
      setReviewNote("");
      setReviewExpiry("");
      onAction();
    },
    onError: (e: Error) => toast({ title: "Action failed", description: e.message, variant: "destructive" }),
  });

  const prob = finding.ai_triage_assessment?.fp_probability;
  const isPending = finding.triage_status === "pending_review";
  const hasDetails = !!(finding.fp_evidence || finding.ai_triage_assessment?.reasoning);

  return (
    <div
      ref={tabRef}
      className={`rounded-lg border transition-all ${focused ? "border-primary ring-1 ring-primary/30" : selected ? "border-primary/50 bg-primary/5" : "border-border/50 hover:border-border"}`}
    >
      <div className="p-4">
        {/* Top row: checkbox + badges + aging */}
        <div className="flex items-start gap-3">
          {isPending && (
            <input
              type="checkbox"
              checked={selected}
              onChange={e => onSelect(finding._id, e.target.checked)}
              className="mt-1 w-4 h-4 rounded accent-primary cursor-pointer shrink-0"
              onClick={e => e.stopPropagation()}
            />
          )}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap mb-1.5">
              <SeverityPill severity={finding.severity} />
              {finding.fp_reason && (
                <span className="text-xs px-2 py-0.5 rounded border border-border bg-muted/50 text-muted-foreground">
                  {REASON_LABELS[finding.fp_reason] ?? finding.fp_reason}
                </span>
              )}
              {finding.fp_marked_at && <AgingBadge markedAt={finding.fp_marked_at} />}
              {finding.fp_expiry_date && (
                <span className="text-xs px-2 py-0.5 rounded border border-yellow-500/30 bg-yellow-500/10 text-yellow-400 flex items-center gap-1">
                  <CalendarClock className="w-3 h-3" />
                  Expires {format(new Date(finding.fp_expiry_date), "MMM d")}
                </span>
              )}
            </div>

            <Link href={`/findings/${finding._id}`}>
              <a className="font-semibold hover:text-primary transition-colors line-clamp-1 flex items-center gap-1 group">
                {finding.title}
                <ExternalLink className="w-3 h-3 opacity-0 group-hover:opacity-60 shrink-0" />
              </a>
            </Link>
            <p className="text-xs text-muted-foreground mt-0.5 font-mono truncate">{finding.endpoint}</p>

            {/* AI probability bar */}
            {prob !== undefined && <AiBar prob={prob} />}
          </div>

          {/* Action buttons (pending only) */}
          {isPending && (
            <div className="flex flex-col gap-1.5 shrink-0">
              {reviewOpen === null ? (
                <>
                  <Button size="sm" variant="outline"
                    className="border-green-500/50 text-green-400 hover:bg-green-500/10 h-8 text-xs gap-1"
                    onClick={() => setReviewOpen("approve")}>
                    <CheckCircle2 className="w-3.5 h-3.5" /> Approve
                  </Button>
                  <Button size="sm" variant="outline"
                    className="border-red-500/50 text-red-400 hover:bg-red-500/10 h-8 text-xs gap-1"
                    onClick={() => setReviewOpen("reject")}>
                    <XCircle className="w-3.5 h-3.5" /> Reject
                  </Button>
                </>
              ) : (
                <button onClick={() => setReviewOpen(null)} className="text-xs text-muted-foreground hover:text-foreground">✕ Cancel</button>
              )}
            </div>
          )}
        </div>

        {/* Inline review form */}
        {reviewOpen && (
          <div className={`mt-3 p-3 rounded-lg border ${reviewOpen === "approve" ? "border-green-500/30 bg-green-500/5" : "border-red-500/30 bg-red-500/5"}`}>
            <p className="text-xs font-semibold mb-2 ${reviewOpen === 'approve' ? 'text-green-400' : 'text-red-400'}">
              {reviewOpen === "approve" ? "Confirm as False Positive" : "Reject — Mark as Real Finding"}
            </p>
            <textarea
              className="w-full bg-background border border-border rounded px-3 py-2 text-xs resize-none h-16 mb-2 focus:outline-none focus:border-primary/50"
              placeholder="Reviewer note (optional — will appear in audit trail)..."
              value={reviewNote}
              onChange={e => setReviewNote(e.target.value)}
            />
            {reviewOpen === "approve" && (
              <div className="flex items-center gap-2 mb-2">
                <span className="text-xs text-muted-foreground shrink-0">FP Expiry:</span>
                <div className="flex gap-1 flex-wrap">
                  {EXPIRY_OPTIONS.map(o => (
                    <button key={o.value}
                      onClick={() => setReviewExpiry(o.value)}
                      className={`text-xs px-2 py-0.5 rounded border transition-colors ${reviewExpiry === o.value ? "border-primary bg-primary/10 text-primary" : "border-border text-muted-foreground hover:border-primary/50"}`}>
                      {o.label}
                    </button>
                  ))}
                </div>
              </div>
            )}
            <div className="flex gap-2 justify-end">
              <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => setReviewOpen(null)}>Cancel</Button>
              <Button size="sm"
                className={`h-7 text-xs text-white ${reviewOpen === "approve" ? "bg-green-600 hover:bg-green-700" : "bg-red-600 hover:bg-red-700"}`}
                disabled={reviewMutation.isPending}
                onClick={() => reviewMutation.mutate({ action: reviewOpen, note: reviewNote, expiry: reviewExpiry })}>
                {reviewMutation.isPending ? <Loader2 className="w-3 h-3 animate-spin mr-1" /> : null}
                {reviewOpen === "approve" ? "Confirm FP" : "Reject FP"}
              </Button>
            </div>
          </div>
        )}

        {/* Marked-by meta row */}
        <div className="mt-3 flex items-center gap-4 text-xs text-muted-foreground">
          <span className="flex items-center gap-1">
            <User className="w-3 h-3" />
            {finding.fp_marked_by ?? "Unknown"}
          </span>
          {finding.fp_marked_at && (
            <span title={format(new Date(finding.fp_marked_at), "MMM d, yyyy HH:mm")}>
              {formatDistanceToNow(new Date(finding.fp_marked_at), { addSuffix: true })}
            </span>
          )}
          {hasDetails && (
            <button
              onClick={() => setExpanded(p => !p)}
              className="ml-auto flex items-center gap-1 text-xs hover:text-foreground transition-colors">
              {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              {expanded ? "Hide details" : "Show details"}
            </button>
          )}
        </div>

        {/* Expandable details */}
        {expanded && (
          <div className="mt-3 space-y-2">
            {finding.fp_evidence && (
              <div className="p-2.5 rounded bg-muted/50 text-xs">
                <p className="text-muted-foreground font-medium mb-0.5">Evidence</p>
                <p className="text-foreground">{finding.fp_evidence}</p>
              </div>
            )}
            {finding.ai_triage_assessment?.reasoning && (
              <div className="p-2.5 rounded bg-blue-500/10 border border-blue-500/20 text-xs text-blue-300">
                <p className="font-medium mb-0.5 flex items-center gap-1"><Brain className="w-3 h-3" />AI Reasoning</p>
                <p>{finding.ai_triage_assessment.reasoning}</p>
              </div>
            )}
          </div>
        )}

        {/* Audit trail (confirmed/rejected tabs) */}
        {(finding.fp_reviewed_at || finding.fp_reviewer_name) && (
          <div className="mt-3 pt-3 border-t border-border/50 flex items-start gap-2 text-xs text-muted-foreground">
            <CheckCircle2 className="w-3.5 h-3.5 mt-0.5 shrink-0 text-green-400" />
            <span>
              Reviewed by <span className="text-foreground font-medium">{finding.fp_reviewer_name ?? finding.fp_reviewer_id ?? "Reviewer"}</span>
              {finding.fp_reviewed_at && <> · {format(new Date(finding.fp_reviewed_at), "MMM d, HH:mm")}</>}
              {finding.fp_reviewer_note && <> · <span className="italic">"{finding.fp_reviewer_note}"</span></>}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function FalsePositivesPage() {
  const { toast } = useToast();
  const qc = useQueryClient();

  const [tab, setTab] = useState("pending_review");
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [reasonFilter, setReasonFilter] = useState("all");
  const [sortBy, setSortBy] = useState<"newest" | "oldest" | "ai_prob" | "severity">("newest");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkLoading, setBulkLoading] = useState(false);
  const [focusedIdx, setFocusedIdx] = useState(0);
  const [showFilters, setShowFilters] = useState(false);
  const cardRefs = useRef<(HTMLDivElement | null)[]>([]);

  // Fetch counts for all tabs in parallel
  const countQueries = TABS.map(t =>
    useQuery({
      queryKey: ["false-positives-count", t.apiStatus],
      queryFn: async () => {
        const res = await fetch(`/api/findings/false-positives?status=${t.apiStatus}&limit=1`, { credentials: "include" });
        if (!res.ok) return 0;
        const d = await res.json() as { total?: number };
        return d.total ?? 0;
      },
      staleTime: 15000,
    })
  );

  const tabCounts = Object.fromEntries(TABS.map((t, i) => [t.value, countQueries[i].data]));

  // Main data query
  const { data, isLoading, refetch } = useQuery({
    queryKey: ["false-positives", tab],
    queryFn: async () => {
      const res = await fetch(`/api/findings/false-positives?status=${tab}&limit=100`, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to load");
      return res.json() as Promise<{ items: FPFinding[]; total: number }>;
    },
  });

  const rawFindings: FPFinding[] = data?.items ?? [];

  // Client-side filter + sort
  const findings = rawFindings
    .filter(f => {
      if (search && !f.title.toLowerCase().includes(search.toLowerCase()) && !f.endpoint.toLowerCase().includes(search.toLowerCase())) return false;
      if (severityFilter !== "all" && f.severity?.toLowerCase() !== severityFilter) return false;
      if (reasonFilter !== "all" && f.fp_reason !== reasonFilter) return false;
      return true;
    })
    .sort((a, b) => {
      if (sortBy === "newest") return new Date(b.fp_marked_at).getTime() - new Date(a.fp_marked_at).getTime();
      if (sortBy === "oldest") return new Date(a.fp_marked_at).getTime() - new Date(b.fp_marked_at).getTime();
      if (sortBy === "ai_prob") return (b.ai_triage_assessment?.fp_probability ?? -1) - (a.ai_triage_assessment?.fp_probability ?? -1);
      if (sortBy === "severity") return (SEVERITY_ORDER[a.severity?.toLowerCase()] ?? 99) - (SEVERITY_ORDER[b.severity?.toLowerCase()] ?? 99);
      return 0;
    });

  // Reset selection when tab changes
  useEffect(() => { setSelected(new Set()); setFocusedIdx(0); }, [tab]);

  // Keyboard shortcuts
  const handleKey = useCallback((e: KeyboardEvent) => {
    const tag = (e.target as HTMLElement).tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
    const pendingFindings = findings.filter(f => f.triage_status === "pending_review");
    if (e.key === "j" || e.key === "ArrowDown") {
      e.preventDefault();
      setFocusedIdx(i => Math.min(i + 1, pendingFindings.length - 1));
    }
    if (e.key === "k" || e.key === "ArrowUp") {
      e.preventDefault();
      setFocusedIdx(i => Math.max(i - 1, 0));
    }
    if (e.key === "a" && tab === "pending_review" && pendingFindings[focusedIdx]) {
      e.preventDefault();
      toast({ title: "Use the Approve button", description: "Click Approve then confirm the review form." });
    }
  }, [findings, focusedIdx, tab, toast]);

  useEffect(() => {
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [handleKey]);

  // Scroll focused card into view
  useEffect(() => {
    cardRefs.current[focusedIdx]?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [focusedIdx]);

  // Bulk actions
  const toggleSelect = (id: string, checked: boolean) => {
    setSelected(prev => {
      const next = new Set(prev);
      checked ? next.add(id) : next.delete(id);
      return next;
    });
  };

  const toggleSelectAll = () => {
    const pending = findings.filter(f => f.triage_status === "pending_review");
    if (selected.size === pending.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(pending.map(f => f._id)));
    }
  };

  const bulkAction = async (action: "approve" | "reject") => {
    if (!selected.size) return;
    setBulkLoading(true);
    let success = 0, failed = 0;
    await Promise.allSettled(
      [...selected].map(id =>
        fetch(`/api/findings/${id}/triage/review`, {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            decision: action,
            notes: action === "approve" ? "Bulk confirmed false positive" : "Bulk rejected — finding is valid",
          }),
        }).then(r => { if (r.ok) success++; else failed++; })
         .catch(() => failed++)
      )
    );
    setBulkLoading(false);
    setSelected(new Set());
    qc.invalidateQueries({ queryKey: ["false-positives"] });
    toast({
      title: `Bulk ${action === "approve" ? "Approval" : "Rejection"} Complete`,
      description: `${success} succeeded${failed ? `, ${failed} failed` : ""}.`,
      variant: failed > 0 ? "destructive" : "default",
    });
  };

  const pendingFindings = findings.filter(f => f.triage_status === "pending_review");

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">

      {/* ── Header ── */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ShieldOff className="w-6 h-6 text-yellow-400" />
            False Positive Review Queue
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Four-eyes review workflow — a second analyst must confirm or reject each FP.
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={() => setShowFilters(p => !p)}
            className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded border border-border hover:border-primary/50 text-muted-foreground hover:text-foreground transition-colors"
            title="Keyboard: J/K to navigate">
            <Keyboard className="w-3.5 h-3.5" />
            Shortcuts
          </button>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* ── Stats Strip ── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {TABS.map((t, i) => {
          const Icon = t.icon;
          const count = countQueries[i].data;
          return (
            <button key={t.value}
              onClick={() => setTab(t.value)}
              className={`text-left rounded-lg border p-4 transition-all hover:border-primary/50 ${tab === t.value ? "border-primary/60 bg-primary/5" : "border-border/50"}`}>
              <div className={`flex items-center gap-1.5 text-xs text-muted-foreground mb-1`}>
                <Icon className={`w-3.5 h-3.5 ${t.color}`} />
                {t.label}
              </div>
              <div className="text-2xl font-bold">
                {count === undefined ? <span className="w-8 h-6 rounded bg-muted animate-pulse inline-block" /> : count}
              </div>
            </button>
          );
        })}
      </div>

      {/* ── Filter / Sort Bar ── */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none" />
          <Input
            placeholder="Search title or endpoint…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="pl-9 h-8 text-xs"
          />
        </div>

        <button onClick={() => setShowFilters(p => !p)}
          className={`inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded border transition-colors ${showFilters ? "border-primary bg-primary/10 text-primary" : "border-border text-muted-foreground hover:border-primary/50"}`}>
          <SlidersHorizontal className="w-3.5 h-3.5" />
          Filters {(severityFilter !== "all" || reasonFilter !== "all") && <span className="bg-primary text-primary-foreground rounded-full w-4 h-4 flex items-center justify-center text-[10px]">!</span>}
        </button>

        <select
          value={sortBy}
          onChange={e => setSortBy(e.target.value as typeof sortBy)}
          className="bg-background border border-border rounded px-2 py-1.5 text-xs text-muted-foreground h-8 cursor-pointer">
          <option value="newest">Newest first</option>
          <option value="oldest">Oldest first</option>
          <option value="ai_prob">AI probability ↓</option>
          <option value="severity">Severity ↓</option>
        </select>

        {findings.length !== rawFindings.length && (
          <span className="text-xs text-muted-foreground">
            Showing {findings.length} of {rawFindings.length}
          </span>
        )}
      </div>

      {/* Expanded filters */}
      {showFilters && (
        <div className="flex flex-wrap gap-4 p-3 rounded-lg border border-border bg-muted/20 text-xs">
          <div className="space-y-1">
            <p className="text-muted-foreground font-medium">Severity</p>
            <div className="flex gap-1 flex-wrap">
              {["all", "critical", "high", "medium", "low", "info"].map(s => (
                <button key={s} onClick={() => setSeverityFilter(s)}
                  className={`px-2 py-0.5 rounded border transition-colors capitalize ${severityFilter === s ? "border-primary bg-primary/10 text-primary" : "border-border text-muted-foreground hover:border-primary/50"}`}>
                  {s === "all" ? "All" : s}
                </button>
              ))}
            </div>
          </div>
          <div className="space-y-1">
            <p className="text-muted-foreground font-medium">Reason</p>
            <div className="flex gap-1 flex-wrap">
              {[["all", "All"], ...Object.entries(REASON_LABELS)].map(([v, l]) => (
                <button key={v} onClick={() => setReasonFilter(v)}
                  className={`px-2 py-0.5 rounded border transition-colors ${reasonFilter === v ? "border-primary bg-primary/10 text-primary" : "border-border text-muted-foreground hover:border-primary/50"}`}>
                  {l}
                </button>
              ))}
            </div>
          </div>
          <button onClick={() => { setSeverityFilter("all"); setReasonFilter("all"); }}
            className="self-end text-xs text-muted-foreground hover:text-foreground underline">
            Clear filters
          </button>
        </div>
      )}

      {/* ── Bulk Action Bar ── */}
      {tab === "pending_review" && selected.size > 0 && (
        <div className="flex items-center gap-3 px-4 py-2.5 rounded-lg border border-primary/40 bg-primary/5">
          <span className="text-sm font-medium">{selected.size} selected</span>
          <div className="flex gap-2 ml-auto">
            <Button size="sm" variant="outline"
              className="border-green-500/50 text-green-400 hover:bg-green-500/10 h-8 text-xs gap-1"
              disabled={bulkLoading}
              onClick={() => bulkAction("approve")}>
              {bulkLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : <CheckCircle2 className="w-3 h-3" />}
              Approve All ({selected.size})
            </Button>
            <Button size="sm" variant="outline"
              className="border-red-500/50 text-red-400 hover:bg-red-500/10 h-8 text-xs gap-1"
              disabled={bulkLoading}
              onClick={() => bulkAction("reject")}>
              {bulkLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : <XCircle className="w-3 h-3" />}
              Reject All ({selected.size})
            </Button>
            <button className="text-xs text-muted-foreground hover:text-foreground" onClick={() => setSelected(new Set())}>
              Clear
            </button>
          </div>
        </div>
      )}

      {/* ── Tabs ── */}
      <Tabs value={tab} onValueChange={t => { setTab(t); setSearch(""); setSeverityFilter("all"); setReasonFilter("all"); }}>
        <TabsList className="bg-muted/50">
          {TABS.map((t, i) => {
            const Icon = t.icon;
            const count = countQueries[i].data;
            return (
              <TabsTrigger key={t.value} value={t.value} className="gap-2">
                <Icon className={`w-3.5 h-3.5 ${t.color}`} />
                {t.label}
                {count !== undefined && count > 0 && (
                  <span className={`ml-1 text-[10px] font-bold px-1.5 py-0.5 rounded-full ${tab === t.value ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground"}`}>
                    {count}
                  </span>
                )}
              </TabsTrigger>
            );
          })}
        </TabsList>

        {TABS.map(t => (
          <TabsContent key={t.value} value={t.value} className="mt-4">
            {/* Select-all row (pending tab only) */}
            {t.value === "pending_review" && !isLoading && pendingFindings.length > 0 && (
              <div className="flex items-center gap-3 mb-3 px-1">
                <input
                  type="checkbox"
                  checked={selected.size === pendingFindings.length && pendingFindings.length > 0}
                  onChange={toggleSelectAll}
                  className="w-4 h-4 rounded accent-primary cursor-pointer"
                />
                <span className="text-xs text-muted-foreground">
                  Select all ({pendingFindings.length})
                </span>
                <span className="ml-auto text-xs text-muted-foreground flex items-center gap-1">
                  <Keyboard className="w-3 h-3" /> J/K to navigate
                </span>
              </div>
            )}

            <div className="space-y-3">
              {isLoading ? (
                Array.from({ length: 3 }).map((_, i) => <SkeletonCard key={i} />)
              ) : findings.length === 0 ? (
                <EmptyState tab={t.value} />
              ) : (
                findings.map((f, idx) => (
                  <FPCard
                    key={f._id}
                    finding={f}
                    focused={tab === "pending_review" && idx === focusedIdx}
                    selected={selected.has(f._id)}
                    onSelect={toggleSelect}
                    onAction={() => qc.invalidateQueries({ queryKey: ["false-positives"] })}
                    tabRef={(el) => { cardRefs.current[idx] = el; }}
                  />
                ))
              )}
            </div>
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );
}
