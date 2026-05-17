import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { useState, useRef } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { format, formatDistanceToNow } from "date-fns";
import {
  Wrench, ExternalLink, LayoutGrid, List,
  AlertTriangle, Clock, CheckCircle2, Eye, X,
  Upload, Trash2, MessageSquare, Activity, UserCircle,
  ThumbsUp, ThumbsDown, RotateCcw,
} from "lucide-react";

const COLUMNS: { id: string; label: string; color: string; icon: React.ReactNode }[] = [
  { id: "pending",     label: "Pending",     color: "#eab308", icon: <Clock className="w-4 h-4" /> },
  { id: "in_progress", label: "In Progress", color: "#3b82f6", icon: <Wrench className="w-4 h-4" /> },
  { id: "review",      label: "In Review",   color: "#a855f7", icon: <Eye className="w-4 h-4" /> },
  { id: "resolved",    label: "Resolved",    color: "#22c55e", icon: <CheckCircle2 className="w-4 h-4" /> },
];

const SEV_COLOR: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22d3ee",
};

// ─── Remediation Detail Panel ─────────────────────────────────────────────────

function RemediationDetailPanel({
  remId,
  rem,
  onClose,
}: {
  remId: string;
  rem: any;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [commentText, setCommentText] = useState("");
  const [rejectOpen, setRejectOpen] = useState(false);
  const [rejectReason, setRejectReason] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Fetch users for assignee dropdown
  const { data: users = [] } = useQuery<any[]>({
    queryKey: ["/api/admin/users"],
    queryFn: () =>
      fetch("/api/admin/users?role=all", { credentials: "include" }).then((r) => r.json()),
    select: (d) => (Array.isArray(d) ? d : (d as any)?.users ?? []),
  });

  // Fetch evidence
  const { data: evidence = [] } = useQuery<any[]>({
    queryKey: [`/api/remediations/${remId}/evidence`],
    queryFn: () =>
      fetch(`/api/remediations/${remId}/evidence`, { credentials: "include" }).then((r) => r.json()),
  });

  // Fetch activity
  const { data: activity = [] } = useQuery<any[]>({
    queryKey: [`/api/remediations/${remId}/activity`],
    queryFn: () =>
      fetch(`/api/remediations/${remId}/activity`, { credentials: "include" }).then((r) => r.json()),
  });

  // Fetch comments
  const { data: comments = [] } = useQuery<any[]>({
    queryKey: [`/api/comments?resource=remediation&resource_id=${remId}`],
    queryFn: () =>
      fetch(`/api/comments?resource=remediation&resource_id=${remId}`, { credentials: "include" }).then((r) => r.json()),
    select: (d) => (Array.isArray(d) ? d : []),
  });

  const patchRemediation = useMutation({
    mutationFn: (patch: Record<string, unknown>) =>
      fetch(`/api/remediations/${remId}`, {
        method: "PATCH",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patch),
      }).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/remediations"] });
      qc.invalidateQueries({ queryKey: [`/api/remediations/${remId}/activity`] });
    },
  });

  const deleteEvidence = useMutation({
    mutationFn: (evidenceId: string) =>
      fetch(`/api/remediations/${remId}/evidence/${evidenceId}`, {
        method: "DELETE",
        credentials: "include",
      }).then((r) => r.json()),
    onSuccess: () => qc.invalidateQueries({ queryKey: [`/api/remediations/${remId}/evidence`] }),
  });

  const postComment = useMutation({
    mutationFn: (body: string) =>
      fetch("/api/comments", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ resource: "remediation", resource_id: remId, body }),
      }).then((r) => r.json()),
    onSuccess: () => {
      setCommentText("");
      qc.invalidateQueries({ queryKey: [`/api/comments?resource=remediation&resource_id=${remId}`] });
    },
  });

  async function handleFileUpload(file: File) {
    const reader = new FileReader();
    reader.onload = async () => {
      const base64 = (reader.result as string).split(",")[1] ?? "";
      await fetch(`/api/remediations/${remId}/evidence`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          filename: file.name,
          content_type: file.type,
          base64_data: base64,
          label: file.name,
        }),
      });
      qc.invalidateQueries({ queryKey: [`/api/remediations/${remId}/evidence`] });
    };
    reader.readAsDataURL(file);
  }

  // Compute SLA info from rem
  const slaDeadline = rem.sla_deadline ? new Date(rem.sla_deadline) : null;
  const now = new Date();
  const slaOverdue = slaDeadline && slaDeadline < now;
  const slaDaysRemaining = slaDeadline
    ? Math.ceil((slaDeadline.getTime() - now.getTime()) / 86400000)
    : null;

  return (
    <>
    <Dialog open onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent className="sm:max-w-xl max-h-[90vh] overflow-y-auto p-0">
        <DialogHeader className="px-6 py-4 border-b border-border sticky top-0 bg-background z-10">
          <DialogTitle className="flex items-center justify-between gap-3">
            <span className="truncate text-base font-semibold">{rem.title}</span>
            <button onClick={onClose} className="flex-shrink-0 text-muted-foreground hover:text-foreground transition-colors">
              <X className="w-4 h-4" />
            </button>
          </DialogTitle>
        </DialogHeader>

        <div className="px-6 py-4 space-y-6">
          {/* ── ASSIGNEE ── */}
          <section>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
              <UserCircle className="w-3.5 h-3.5" /> Assignee
            </h3>
            {rem.assignee_name && (
              <Badge variant="outline" className="mb-2 text-xs">{rem.assignee_name}</Badge>
            )}
            <select
              className="text-xs rounded border border-border bg-background px-2 py-1.5 w-full"
              defaultValue={rem.assignee_id ?? ""}
              onChange={(e) => {
                const selected = users.find((u: any) => u.id === e.target.value);
                patchRemediation.mutate({
                  assignee_id: e.target.value,
                  assignee_name: selected?.username ?? selected?.email ?? "",
                });
              }}
            >
              <option value="">— Assign to —</option>
              {users.map((u: any) => (
                <option key={u.id} value={u.id}>{u.username ?? u.email}</option>
              ))}
            </select>
          </section>

          {/* ── APPROVAL WORKFLOW ── */}
          <section>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" /> Workflow
            </h3>
            <div className="flex flex-wrap gap-2">
              {rem.status === "in_progress" && (
                <Button
                  size="sm"
                  variant="outline"
                  className="text-xs gap-1.5"
                  onClick={() => patchRemediation.mutate({ status: "review" })}
                >
                  <Eye className="w-3.5 h-3.5" /> Request Review
                </Button>
              )}
              {rem.status === "review" && (
                <>
                  <Button
                    size="sm"
                    className="text-xs gap-1.5 bg-green-600 hover:bg-green-700"
                    onClick={() =>
                      patchRemediation.mutate({
                        status: "resolved",
                        approved_at: new Date().toISOString(),
                      })
                    }
                  >
                    <ThumbsUp className="w-3.5 h-3.5" /> Approve Fix
                  </Button>
                  <Button
                    size="sm"
                    variant="destructive"
                    className="text-xs gap-1.5"
                    onClick={() => setRejectOpen(true)}
                  >
                    <ThumbsDown className="w-3.5 h-3.5" /> Reject Fix
                  </Button>
                </>
              )}
              {rem.status === "resolved" && (
                <Button
                  size="sm"
                  variant="outline"
                  className="text-xs gap-1.5"
                  onClick={() => patchRemediation.mutate({ status: "in_progress" })}
                >
                  <RotateCcw className="w-3.5 h-3.5" /> Reopen
                </Button>
              )}
            </div>
          </section>

          {/* ── SLA ── */}
          {slaDeadline && (
            <section>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5" /> SLA
              </h3>
              <div className={`text-sm font-medium ${slaOverdue ? "text-destructive" : "text-foreground"}`}>
                {slaOverdue
                  ? `OVERDUE by ${Math.abs(slaDaysRemaining!)} day(s)`
                  : `${slaDaysRemaining} day(s) remaining`}
              </div>
              <div className="text-xs text-muted-foreground mt-0.5">
                Deadline: {format(slaDeadline, "MMM d, yyyy")}
              </div>
            </section>
          )}

          {/* ── EVIDENCE ── */}
          <section>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
              <Upload className="w-3.5 h-3.5" /> Evidence
            </h3>
            <div
              className="border-2 border-dashed border-border rounded-lg p-4 text-center text-xs text-muted-foreground cursor-pointer hover:border-primary/40 transition-colors"
              onClick={() => fileInputRef.current?.click()}
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                const file = e.dataTransfer.files[0];
                if (file) handleFileUpload(file);
              }}
            >
              <Upload className="w-4 h-4 mx-auto mb-1" />
              Click or drop file to upload
            </div>
            <input
              ref={fileInputRef}
              type="file"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) handleFileUpload(file);
              }}
            />
            {evidence.length > 0 && (
              <div className="mt-2 space-y-1">
                {evidence.map((ev: any) => (
                  <div key={ev.id} className="flex items-center justify-between text-xs bg-muted/40 rounded px-2 py-1.5">
                    <span className="truncate max-w-[240px]">{ev.filename}</span>
                    <button
                      onClick={() => deleteEvidence.mutate(ev.id)}
                      className="text-muted-foreground hover:text-destructive transition-colors ml-2"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* ── ACTIVITY FEED ── */}
          <section>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5" /> Activity
            </h3>
            {activity.length === 0 ? (
              <p className="text-xs text-muted-foreground">No activity yet.</p>
            ) : (
              <div className="space-y-2">
                {activity.map((a: any, i: number) => (
                  <div key={i} className="flex items-start gap-2 text-xs">
                    <Clock className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0 mt-0.5" />
                    <div>
                      <span className="font-medium">{String(a.actor ?? "Unknown")}</span>
                      {" "}{String(a.action ?? "")}
                      {a.details ? ` — ${String(a.details)}` : ""}
                      {" · "}
                      <span className="text-muted-foreground">
                        {a.timestamp ? formatDistanceToNow(new Date(a.timestamp), { addSuffix: true }) : ""}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* ── COMMENTS ── */}
          <section>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
              <MessageSquare className="w-3.5 h-3.5" /> Comments
            </h3>
            <div className="space-y-2 mb-3">
              {comments.map((c: any, i: number) => (
                <div key={i} className="text-xs bg-muted/40 rounded px-3 py-2">
                  <span className="font-medium text-foreground">{String(c.author ?? c.user ?? "User")}</span>
                  <span className="text-muted-foreground ml-2">
                    {c.created_at ? formatDistanceToNow(new Date(c.created_at), { addSuffix: true }) : ""}
                  </span>
                  <p className="mt-0.5 text-muted-foreground">{String(c.body ?? c.text ?? "")}</p>
                </div>
              ))}
            </div>
            <textarea
              className="w-full text-xs rounded border border-border bg-background px-3 py-2 resize-none outline-none focus:border-primary/60 transition-colors"
              rows={3}
              placeholder="Add a comment…"
              value={commentText}
              onChange={(e) => setCommentText(e.target.value)}
            />
            <Button
              size="sm"
              className="mt-1.5 text-xs"
              disabled={!commentText.trim() || postComment.isPending}
              onClick={() => postComment.mutate(commentText.trim())}
            >
              Submit
            </Button>
          </section>
        </div>
      </DialogContent>
    </Dialog>
    <RejectDialog
      open={rejectOpen}
      onClose={() => setRejectOpen(false)}
      onConfirm={(reason) => {
        patchRemediation.mutate({ status: "in_progress", rejection_reason: reason });
        setRejectOpen(false);
      }}
    />
    </>
  );
}

function RejectDialog({
  open,
  onClose,
  onConfirm,
}: {
  open: boolean;
  onClose: () => void;
  onConfirm: (reason: string) => void;
}) {
  const [reason, setReason] = useState("");
  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Reject Fix</DialogTitle>
        </DialogHeader>
        <textarea
          className="w-full text-sm rounded border border-border bg-background px-3 py-2 resize-none outline-none focus:border-primary/60 transition-colors"
          rows={4}
          placeholder="Reason for rejection…"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button
            variant="destructive"
            disabled={!reason.trim()}
            onClick={() => { onConfirm(reason.trim()); setReason(""); }}
          >
            Reject
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Kanban Card ──────────────────────────────────────────────────────────────

function RemCard({
  rem,
  onDragStart,
  onNavigate,
  onClick,
}: {
  rem: any;
  onDragStart: (e: React.DragEvent, id: string) => void;
  onNavigate: (path: string) => void;
  onClick: (id: string) => void;
}) {
  return (
    <div
      draggable
      onDragStart={(e) => onDragStart(e, rem.id)}
      onClick={() => onClick(rem.id)}
      className="group rounded-lg border border-border bg-card p-3 cursor-pointer active:cursor-grabbing hover:border-primary/40 transition-all select-none"
      style={{ boxShadow: "0 1px 4px rgba(0,0,0,.15)" }}
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <p className="text-sm font-medium leading-snug line-clamp-2">{rem.title}</p>
        {rem.sla_breached && (
          <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 text-destructive mt-0.5" />
        )}
      </div>

      {rem.description && (
        <p className="text-[11px] text-muted-foreground mb-2 line-clamp-2">{rem.description}</p>
      )}

      <div className="flex items-center justify-between mt-2">
        <div className="flex gap-1.5">
          {rem.severity && (
            <span
              className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded"
              style={{ background: `${SEV_COLOR[rem.severity] ?? "#6b7280"}22`, color: SEV_COLOR[rem.severity] ?? "#6b7280" }}
            >
              {rem.severity}
            </span>
          )}
        </div>
        <div className="flex items-center gap-1.5 opacity-0 group-hover:opacity-100 transition-opacity">
          {rem.finding_id && (
            <button
              className="text-[10px] text-muted-foreground hover:text-foreground flex items-center gap-0.5"
              onClick={(e) => { e.stopPropagation(); onNavigate(`/findings/${rem.finding_id}`); }}
            >
              <ExternalLink className="w-3 h-3" /> Finding
            </button>
          )}
        </div>
      </div>

      <div className="mt-2 text-[10px] text-muted-foreground font-mono">
        {format(new Date(rem.created_at), "MMM d, yyyy")}
      </div>
    </div>
  );
}

function KanbanColumn({
  col,
  items,
  onDragStart,
  onDrop,
  onNavigate,
  onCardClick,
}: {
  col: typeof COLUMNS[0];
  items: any[];
  onDragStart: (e: React.DragEvent, id: string) => void;
  onDrop: (status: string) => void;
  onNavigate: (path: string) => void;
  onCardClick: (id: string) => void;
}) {
  const [over, setOver] = useState(false);

  return (
    <div
      className="flex flex-col min-w-[260px] flex-1 rounded-xl border border-border"
      style={{ background: "hsl(var(--card))" }}
      onDragOver={(e) => { e.preventDefault(); setOver(true); }}
      onDragLeave={() => setOver(false)}
      onDrop={() => { setOver(false); onDrop(col.id); }}
    >
      {/* Column header */}
      <div
        className="flex items-center gap-2 px-4 py-3 rounded-t-xl border-b border-border"
        style={{ background: `${col.color}12`, borderTop: `3px solid ${col.color}` }}
      >
        <span style={{ color: col.color }}>{col.icon}</span>
        <span className="font-semibold text-sm">{col.label}</span>
        <span
          className="ml-auto text-xs font-bold px-2 py-0.5 rounded-full"
          style={{ background: `${col.color}22`, color: col.color }}
        >
          {items.length}
        </span>
      </div>

      {/* Cards */}
      <div
        className="flex-1 p-3 space-y-2.5 overflow-y-auto"
        style={{
          minHeight: 120,
          background: over ? `${col.color}08` : undefined,
          transition: "background 0.15s",
        }}
      >
        {items.length === 0 && (
          <div className="text-xs text-muted-foreground text-center py-6 border border-dashed border-border rounded-lg">
            Drop here
          </div>
        )}
        {items.map((r) => (
          <RemCard key={r.id} rem={r} onDragStart={onDragStart} onNavigate={onNavigate} onClick={onCardClick} />
        ))}
      </div>
    </div>
  );
}

export default function Remediations() {
  const [, setLocation] = useLocation();
  const [view, setView] = useState<"kanban" | "list">("kanban");
  const [selectedRemediationId, setSelectedRemediationId] = useState<string | null>(null);
  const dragId = useRef<string | null>(null);
  const qc = useQueryClient();

  const { data, isLoading, isError } = useQuery<any[]>({
    queryKey: ["/api/remediations"],
    queryFn: () =>
      fetch("/api/remediations?limit=200", { credentials: "include" }).then((r) => r.json()),
    select: (d) => (Array.isArray(d) ? d : (d as any)?.items ?? []),
  });

  if (isError) return (
    <div className="flex flex-col items-center justify-center h-64 gap-4">
      <AlertTriangle className="w-12 h-12 text-red-400" />
      <p className="text-muted-foreground text-sm">Failed to load data. Please try again.</p>
      <Button variant="outline" size="sm" onClick={() => window.location.reload()}>Retry</Button>
    </div>
  );

  const updateStatus = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      fetch(`/api/remediations/${id}`, {
        method: "PATCH",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      }).then((r) => r.json()),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["/api/remediations"] }),
  });

  const remediations: any[] = data ?? [];

  function onDragStart(e: React.DragEvent, id: string) {
    dragId.current = id;
    e.dataTransfer.effectAllowed = "move";
  }

  function onDrop(status: string) {
    if (!dragId.current) return;
    const rem = remediations.find((r) => r.id === dragId.current);
    if (rem && rem.status !== status) {
      updateStatus.mutate({ id: dragId.current, status });
    }
    dragId.current = null;
  }

  const byStatus = (s: string) => remediations.filter((r) => r.status === s);
  const selectedRemediation = selectedRemediationId ? remediations.find((r) => r.id === selectedRemediationId) ?? null : null;

  const stats = {
    total: remediations.length,
    pending: byStatus("pending").length,
    in_progress: byStatus("in_progress").length,
    resolved: byStatus("resolved").length,
    breached: remediations.filter((r) => r.sla_breached).length,
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
            <Wrench className="w-7 h-7" />
            Remediations
          </h1>
          <p className="text-muted-foreground mt-1">
            Drag cards between columns to update status.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant={view === "kanban" ? "default" : "outline"}
            size="sm"
            onClick={() => setView("kanban")}
          >
            <LayoutGrid className="w-4 h-4 mr-1.5" /> Kanban
          </Button>
          <Button
            variant={view === "list" ? "default" : "outline"}
            size="sm"
            onClick={() => setView("list")}
          >
            <List className="w-4 h-4 mr-1.5" /> List
          </Button>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: "Total", value: stats.total, color: "#6d28d9" },
          { label: "Pending", value: stats.pending, color: "#eab308" },
          { label: "In Progress", value: stats.in_progress, color: "#3b82f6" },
          { label: "Resolved", value: stats.resolved, color: "#22c55e" },
        ].map((s) => (
          <Card key={s.label} className="p-4">
            <div className="text-2xl font-bold" style={{ color: s.color }}>{s.value}</div>
            <div className="text-xs text-muted-foreground mt-0.5">{s.label}</div>
          </Card>
        ))}
      </div>

      {stats.breached > 0 && (
        <div className="flex items-center gap-2 px-4 py-3 rounded-lg border border-destructive/30 bg-destructive/10 text-sm text-destructive">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          <span><strong>{stats.breached}</strong> remediation{stats.breached !== 1 ? "s" : ""} have breached SLA deadlines.</span>
        </div>
      )}

      {isLoading ? (
        <div className="p-6 space-y-3">
          <Skeleton className="h-8 w-64" />
          {Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} className="h-12 w-full rounded" />)}
        </div>
      ) : remediations.length === 0 && !isLoading ? (
        <div className="flex flex-col items-center justify-center py-16 gap-4 text-center">
          <CheckCircle2 className="w-16 h-16 text-green-500/30" />
          <div>
            <p className="text-lg font-medium">No remediations</p>
            <p className="text-sm text-muted-foreground mt-1">Remediations will appear here once findings are assigned</p>
          </div>
        </div>
      ) : view === "kanban" ? (
        /* ── KANBAN ── */
        <div className="flex gap-4 overflow-x-auto pb-4" style={{ minHeight: 400 }}>
          {COLUMNS.map((col) => (
            <KanbanColumn
              key={col.id}
              col={col}
              items={byStatus(col.id)}
              onDragStart={onDragStart}
              onDrop={onDrop}
              onNavigate={setLocation}
              onCardClick={setSelectedRemediationId}
            />
          ))}
        </div>
      ) : (
        /* ── LIST ── */
        <div className="space-y-3">
          {remediations.length === 0 ? (
            <div className="p-12 text-center text-muted-foreground border border-dashed border-border rounded-lg">
              No remediation tasks. Create one from a finding detail page.
            </div>
          ) : (
            remediations.map((r) => {
              const col = COLUMNS.find((c) => c.id === r.status) ?? COLUMNS[0];
              return (
                <Card key={r.id} className="overflow-hidden">
                  <div className="flex flex-col md:flex-row">
                    <div className="flex-1 p-5">
                      <div className="flex items-center gap-3 mb-2">
                        <span style={{ color: col.color }}>{col.icon}</span>
                        <h3 className="font-semibold">{r.title}</h3>
                        <Badge
                          variant="outline"
                          className="ml-auto capitalize text-xs"
                          style={{ borderColor: `${col.color}40`, color: col.color, background: `${col.color}12` }}
                        >
                          {col.label}
                        </Badge>
                        {r.sla_breached && (
                          <Badge variant="destructive" className="text-xs">SLA Breached</Badge>
                        )}
                      </div>
                      {r.description && (
                        <p className="text-sm text-muted-foreground mb-3">{r.description}</p>
                      )}
                      <div className="text-xs text-muted-foreground">
                        Created {format(new Date(r.created_at), "MMM d, yyyy")}
                      </div>
                    </div>
                    <div className="bg-muted/30 p-4 md:w-52 border-t md:border-t-0 md:border-l border-border flex flex-col gap-2 justify-center">
                      <Button
                        variant="outline"
                        size="sm"
                        className="w-full text-xs"
                        onClick={() => setSelectedRemediationId(r.id)}
                      >
                        <Eye className="w-3.5 h-3.5 mr-1.5" />Details
                      </Button>
                      <select
                        className="text-xs rounded border border-border bg-background px-2 py-1.5 w-full"
                        value={r.status}
                        onChange={(e) => updateStatus.mutate({ id: r.id, status: e.target.value })}
                      >
                        {COLUMNS.map((c) => (
                          <option key={c.id} value={c.id}>{c.label}</option>
                        ))}
                      </select>
                      {r.finding_id && (
                        <Button
                          variant="outline"
                          size="sm"
                          className="w-full text-xs"
                          onClick={() => setLocation(`/findings/${r.finding_id}`)}
                        >
                          <ExternalLink className="w-3.5 h-3.5 mr-1.5" />View Finding
                        </Button>
                      )}
                    </div>
                  </div>
                </Card>
              );
            })
          )}
        </div>
      )}

      {/* Detail slide-over panel */}
      {selectedRemediationId && selectedRemediation && (
        <RemediationDetailPanel
          remId={selectedRemediationId}
          rem={selectedRemediation}
          onClose={() => setSelectedRemediationId(null)}
        />
      )}
    </div>
  );
}
