import { useState } from "react";
import { useLocation } from "wouter";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import {
  Search, Plus, Trash2, Eye, MoreHorizontal, Download, StopCircle,
  ChevronLeft, ChevronRight, Activity, Sparkles, CheckSquare, Square,
  AlertCircle, Shield, GitCompare,
} from "lucide-react";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { format } from "date-fns";
import { useToast } from "@/hooks/use-toast";
import { TableSkeleton } from "@/components/loading-skeleton";
import { ConfirmDialog } from "@/components/confirm-dialog";

// ── Status badge ──────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const cfg: Record<string, { label: string; bg: string; color: string; border: string }> = {
    queued:    { label: "QUEUED",    bg: "transparent",           color: "#94a3b8", border: "rgba(148,163,184,0.3)" },
    running:   { label: "RUNNING",   bg: "rgba(34,211,238,0.15)", color: "#22d3ee", border: "rgba(34,211,238,0.35)" },
    completed: { label: "COMPLETED", bg: "rgba(74,222,128,0.15)", color: "#4ade80", border: "rgba(74,222,128,0.35)" },
    failed:    { label: "FAILED",    bg: "rgba(248,113,113,0.15)",color: "#f87171", border: "rgba(248,113,113,0.35)" },
    cancelled: { label: "CANCELLED", bg: "transparent",           color: "#94a3b8", border: "rgba(148,163,184,0.3)" },
  };
  const c = cfg[status.toLowerCase()] ?? cfg.queued;
  return (
    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-sm"
      style={{ background: c.bg, color: c.color, border: `1px solid ${c.border}` }}>
      {c.label}
    </span>
  );
}

// ── Severity pill badges (replaces old SeverityDot) ──────────────────────────

const SEV_PILLS: Record<string, { bg: string; color: string; border: string }> = {
  critical: { bg: "rgba(239,68,68,0.15)",  color: "#ef4444", border: "rgba(239,68,68,0.4)" },
  high:     { bg: "rgba(249,115,22,0.15)", color: "#f97316", border: "rgba(249,115,22,0.4)" },
  medium:   { bg: "rgba(234,179,8,0.15)",  color: "#ca8a04", border: "rgba(234,179,8,0.4)" },
  low:      { bg: "rgba(34,211,238,0.15)", color: "#22d3ee", border: "rgba(34,211,238,0.4)" },
};

function SeverityPill({ label, count }: { label: string; count: number }) {
  if (!count) return null;
  const s = SEV_PILLS[label] ?? SEV_PILLS.low;
  return (
    <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold px-1.5 py-0.5 rounded-sm"
      style={{ background: s.bg, color: s.color, border: `1px solid ${s.border}` }}>
      {label.slice(0, 1).toUpperCase()} {count}
    </span>
  );
}

// ── Empty state ───────────────────────────────────────────────────────────────

function FilterEmptyState() {
  return (
    <tr>
      <td colSpan={8} className="px-4 py-16 text-center">
        <div className="flex flex-col items-center gap-3">
          <div className="w-12 h-12 rounded-full flex items-center justify-center"
            style={{ background: "hsl(var(--muted))" }}>
            <Search className="w-6 h-6" style={{ color: "hsl(var(--muted-foreground))" }} />
          </div>
          <p className="text-sm font-medium" style={{ color: "hsl(var(--foreground))" }}>
            No scans match your filter — try clearing filters
          </p>
        </div>
      </td>
    </tr>
  );
}

function NoScansEmptyState({ onNewScan }: { onNewScan: () => void }) {
  return (
    <div className="flex flex-col items-center gap-4 py-24 text-center">
      <div className="w-16 h-16 rounded-2xl flex items-center justify-center"
        style={{ background: "linear-gradient(135deg, rgba(124,58,237,0.2), rgba(168,85,247,0.1))", border: "1px solid rgba(124,58,237,0.3)" }}>
        <Activity className="w-8 h-8" style={{ color: "#a855f7" }} />
      </div>
      <div className="space-y-1">
        <p className="text-sm font-semibold" style={{ color: "hsl(var(--foreground))" }}>No scans yet</p>
        <p className="text-xs max-w-[260px]" style={{ color: "hsl(var(--muted-foreground))" }}>
          Start your first security scan to discover vulnerabilities
        </p>
      </div>
      <Button onClick={onNewScan} size="sm"
        style={{ background: "linear-gradient(135deg, #7c3aed, #a855f7)", color: "white", border: "none" }}>
        <Plus className="w-4 h-4 mr-1.5" />New Scan
      </Button>
    </div>
  );
}

// ── Bulk action toolbar ───────────────────────────────────────────────────────

function BulkToolbar({
  selectedIds,
  onDelete,
  onCancel,
  scans,
  isDeleting,
}: {
  selectedIds: Set<string>;
  onDelete: () => void;
  onCancel: () => void;
  scans: any[];
  isDeleting: boolean;
}) {
  if (selectedIds.size === 0) return null;
  const hasRunning = scans.filter(s => selectedIds.has(s.id)).some(s => s.status === "running" || s.status === "queued");

  return (
    <div className="flex items-center gap-3 px-4 py-2.5 rounded-lg"
      style={{ background: "rgba(124,58,237,0.1)", border: "1px solid rgba(124,58,237,0.3)" }}>
      <span className="text-sm font-semibold" style={{ color: "#a855f7" }}>
        {selectedIds.size} selected
      </span>
      <div className="flex items-center gap-2 ml-auto">
        {hasRunning && (
          <Button size="sm" variant="outline"
            className="border-orange-500/40 text-orange-400 hover:bg-orange-500/10 h-7 text-xs"
            onClick={onCancel}>
            <StopCircle className="w-3.5 h-3.5 mr-1.5" />Cancel Selected
          </Button>
        )}
        <Button size="sm" variant="outline"
          className="border-destructive/40 text-destructive hover:bg-destructive/10 h-7 text-xs"
          onClick={onDelete} disabled={isDeleting}>
          <Trash2 className="w-3.5 h-3.5 mr-1.5" />Delete Selected
        </Button>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

const PAGE_SIZE = 20;

export default function Scans() {
  const [, setLocation] = useLocation();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [page, setPage] = useState(1);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [confirmCancel, setConfirmCancel] = useState<string | null>(null);
  const [confirmBulkDelete, setConfirmBulkDelete] = useState(false);
  const [confirmBulkCancel, setConfirmBulkCancel] = useState(false);
  const { toast } = useToast();
  const qc = useQueryClient();

  const params = new URLSearchParams({
    page: String(page),
    page_size: String(PAGE_SIZE),
    ...(search ? { search } : {}),
    ...(statusFilter !== "all" ? { status: statusFilter } : {}),
  });

  const { data, isLoading } = useQuery({
    queryKey: ["/api/scan-jobs", page, search, statusFilter],
    queryFn: () =>
      fetch(`/api/scan-jobs?${params}`, { credentials: "include" }).then(r => r.json()),
    refetchInterval: 5000,
  });

  const scans: any[] = data?.items ?? [];
  const totalPages = Math.ceil((data?.total ?? 0) / PAGE_SIZE);

  const deleteScan = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/scan-jobs/${id}`, { method: "DELETE", credentials: "include", headers: { "Content-Type": "application/json" } }).then(async r => {
        if (!r.ok) throw new Error(await r.text());
      }),
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: ["/api/scan-jobs"] });
      setSelectedIds(prev => { const n = new Set(prev); n.delete(id); return n; });
      toast({ title: "Scan deleted", description: "The scan and its findings have been removed." });
    },
    onError: () => toast({ title: "Delete failed", description: "Could not delete the scan. Please try again.", variant: "destructive" }),
  });

  const cancelScan = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/scan-jobs/${id}/cancel`, { method: "POST", credentials: "include", headers: { "Content-Type": "application/json" } }).then(async r => {
        if (!r.ok) throw new Error(await r.text());
        return r.json();
      }),
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: ["/api/scan-jobs"] });
      toast({ title: "Scan cancelled", description: `Scan ${id.slice(0, 8)} has been cancelled.` });
    },
    onError: () => toast({ title: "Cancel failed", description: "Could not cancel the scan. It may have already completed.", variant: "destructive" }),
  });

  async function bulkDelete() {
    for (const id of Array.from(selectedIds)) {
      await fetch(`/api/scan-jobs/${id}`, { method: "DELETE", credentials: "include", headers: { "Content-Type": "application/json" } });
    }
    qc.invalidateQueries({ queryKey: ["/api/scan-jobs"] });
    toast({ title: `${selectedIds.size} scans deleted` });
    setSelectedIds(new Set());
    setConfirmBulkDelete(false);
  }

  async function bulkCancel() {
    const running = scans.filter(s => selectedIds.has(s.id) && (s.status === "running" || s.status === "queued"));
    for (const s of running) {
      await fetch(`/api/scan-jobs/${s.id}/cancel`, { method: "POST", credentials: "include", headers: { "Content-Type": "application/json" } });
    }
    qc.invalidateQueries({ queryKey: ["/api/scan-jobs"] });
    toast({ title: `${running.length} scans cancelled` });
    setSelectedIds(new Set());
    setConfirmBulkCancel(false);
  }

  function exportCSV() { window.open(`/api/scan-jobs/export/csv?${params}`, "_blank"); }
  function exportJSON() { window.open(`/api/scan-jobs/export/json?${params}`, "_blank"); }

  async function compareWithPrevious(scan: any) {
    try {
      const res = await fetch(
        `/api/scan-jobs?target_url=${encodeURIComponent(scan.target_url)}&page_size=20`,
        { credentials: "include" }
      );
      const data = await res.json();
      const others: any[] = (data?.items ?? []).filter((s: any) => s.id !== scan.id);
      if (others.length === 0) {
        toast({ title: "No previous scan found for this target" });
        return;
      }
      // Most recent previous scan
      const prev = others.sort((a: any, b: any) =>
        new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
      )[0];
      setLocation(`/scans/compare?a=${prev.id}&b=${scan.id}`);
    } catch {
      toast({ title: "Failed to fetch scans", variant: "destructive" });
    }
  }

  function handleSearch(v: string) { setSearch(v); setPage(1); setSelectedIds(new Set()); }
  function handleStatus(v: string) { setStatusFilter(v); setPage(1); setSelectedIds(new Set()); }

  function toggleSelect(id: string) {
    setSelectedIds(prev => {
      const n = new Set(prev);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });
  }

  function toggleSelectAll() {
    if (selectedIds.size === scans.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(scans.map(s => s.id)));
    }
  }

  const allSelected = scans.length > 0 && selectedIds.size === scans.length;
  const someSelected = selectedIds.size > 0 && selectedIds.size < scans.length;
  const statuses = ["all", "queued", "running", "completed", "failed", "cancelled"];
  const hasFilters = !!(search || statusFilter !== "all");

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Scans</h1>
          <p className="text-xs mt-0.5" style={{ color: "hsl(var(--muted-foreground))" }}>
            Manage and view all vulnerability scans.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={exportCSV}>
            <Download className="w-4 h-4 mr-1.5" />CSV
          </Button>
          <Button variant="outline" size="sm" onClick={exportJSON}>
            <Download className="w-4 h-4 mr-1.5" />JSON
          </Button>
          <Button
            onClick={() => setLocation("/scans/new")}
            className="text-sm font-semibold"
            style={{ background: "linear-gradient(135deg, #7c3aed, #a855f7)", color: "white", border: "none" }}
          >
            <Plus className="w-4 h-4 mr-1.5" />NEW SCAN
          </Button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2 px-3 py-2 rounded-md text-sm flex-1 max-w-xs"
          style={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))" }}>
          <Search className="w-3.5 h-3.5 flex-shrink-0" style={{ color: "hsl(var(--muted-foreground))" }} />
          <input
            type="text"
            placeholder="Search target or ID…"
            className="bg-transparent border-none outline-none text-sm w-full"
            value={search}
            onChange={(e) => handleSearch(e.target.value)}
          />
        </div>
        <div className="flex items-center gap-1.5 flex-wrap">
          {statuses.map((s) => {
            const active = statusFilter === s;
            return (
              <button key={s} onClick={() => handleStatus(s)}
                className="text-[10px] font-mono font-semibold px-2.5 py-1 rounded-sm capitalize transition-all"
                style={active
                  ? { background: "hsl(var(--primary))", color: "white" }
                  : { background: "hsl(var(--card))", color: "hsl(var(--muted-foreground))", border: "1px solid hsl(var(--border))" }
                }>
                {s === "all" ? "All" : s}
              </button>
            );
          })}
        </div>
      </div>

      {/* Bulk action toolbar */}
      <BulkToolbar
        selectedIds={selectedIds}
        scans={scans}
        isDeleting={deleteScan.isPending}
        onDelete={() => setConfirmBulkDelete(true)}
        onCancel={() => setConfirmBulkCancel(true)}
      />

      {/* Table */}
      {isLoading ? (
        <TableSkeleton rows={8} cols={7} />
      ) : scans.length === 0 && !hasFilters ? (
        <NoScansEmptyState onNewScan={() => setLocation("/scans/new")} />
      ) : (
        <div className="rounded-lg border overflow-x-auto"
          style={{ background: "hsl(var(--card))", borderColor: "hsl(var(--border))" }}>
          <table className="w-full text-sm min-w-[700px]">
            <thead>
              <tr className="text-[10px] font-mono font-semibold uppercase tracking-wider border-b"
                style={{ color: "hsl(var(--muted-foreground))", borderColor: "hsl(var(--border))", background: "hsl(var(--sidebar))" }}>
                <th className="px-4 py-3 w-8">
                  <button onClick={toggleSelectAll} className="flex items-center justify-center">
                    {allSelected ? (
                      <CheckSquare className="w-4 h-4" style={{ color: "hsl(var(--primary))" }} />
                    ) : someSelected ? (
                      <div className="w-4 h-4 rounded-sm border-2 flex items-center justify-center"
                        style={{ borderColor: "hsl(var(--primary))", background: "hsl(var(--primary)/0.2)" }}>
                        <div className="w-2 h-0.5 rounded" style={{ background: "hsl(var(--primary))" }} />
                      </div>
                    ) : (
                      <Square className="w-4 h-4 opacity-40" />
                    )}
                  </button>
                </th>
                <th className="px-4 py-3 text-left">ID</th>
                <th className="px-4 py-3 text-left">Target</th>
                <th className="px-4 py-3 text-left">Status</th>
                <th className="px-4 py-3 text-left">Profile</th>
                <th className="px-4 py-3 text-left">Findings</th>
                <th className="px-4 py-3 text-left">Started</th>
                <th className="px-4 py-3 text-right"></th>
              </tr>
            </thead>
            <tbody className="divide-y" style={{ borderColor: "hsl(var(--border))" }}>
              {scans.length === 0 ? (
                <FilterEmptyState />
              ) : (
                scans.map((scan) => {
                  const isSelected = selectedIds.has(scan.id);
                  return (
                    <tr key={scan.id}
                      className="transition-colors cursor-pointer"
                      style={{ background: isSelected ? "hsl(var(--primary)/0.05)" : "" }}
                      onMouseEnter={(e) => {
                        if (!isSelected) (e.currentTarget as HTMLElement).style.background = "hsl(var(--muted))";
                      }}
                      onMouseLeave={(e) => {
                        (e.currentTarget as HTMLElement).style.background = isSelected ? "hsl(var(--primary)/0.05)" : "";
                      }}
                      onClick={() => setLocation(`/scans/${scan.id}`)}>
                      {/* Checkbox */}
                      <td className="px-4 py-3 w-8" onClick={(e) => { e.stopPropagation(); toggleSelect(scan.id); }}>
                        {isSelected ? (
                          <CheckSquare className="w-4 h-4" style={{ color: "hsl(var(--primary))" }} />
                        ) : (
                          <Square className="w-4 h-4 opacity-30 hover:opacity-70 transition-opacity" />
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span className="font-mono text-xs" style={{ color: "#22d3ee" }}>{String(scan.id).slice(0, 8)}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="font-mono text-xs">{scan.target_url}</span>
                      </td>
                      <td className="px-4 py-3"><StatusBadge status={scan.status} /></td>
                      <td className="px-4 py-3">
                        <span className="text-[10px] font-mono uppercase tracking-wider" style={{ color: "hsl(var(--muted-foreground))" }}>{scan.scan_profile}</span>
                      </td>
                      <td className="px-4 py-3">
                        {scan.findings_count > 0 ? (
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <SeverityPill label="critical" count={scan.critical_count} />
                            <SeverityPill label="high" count={scan.high_count} />
                            <SeverityPill label="medium" count={scan.medium_count} />
                            <span className="text-xs font-mono" style={{ color: "hsl(var(--muted-foreground))" }}>{scan.findings_count} total</span>
                          </div>
                        ) : (
                          <span className="text-xs font-mono" style={{ color: "hsl(var(--muted-foreground))" }}>
                            {scan.status === "completed" ? "0 total" : "—"}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-xs font-mono" style={{ color: "hsl(var(--muted-foreground))" }}>
                          {format(new Date(scan.created_at), "M/d/yyyy, h:mm aa")}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right" onClick={(e) => e.stopPropagation()}>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" className="h-7 w-7 p-0"><MoreHorizontal className="h-4 w-4" /></Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => setLocation(`/scans/${scan.id}`)}>
                              <Eye className="mr-2 h-4 w-4" />View Details
                            </DropdownMenuItem>
                            {scan.status === "completed" && (
                              <DropdownMenuItem onClick={() => setLocation(`/ai-triage`)}>
                                <Sparkles className="mr-2 h-4 w-4" />AI Triage
                              </DropdownMenuItem>
                            )}
                            <DropdownMenuItem onClick={() => compareWithPrevious(scan)}>
                              <GitCompare className="mr-2 h-4 w-4" />Compare with Previous
                            </DropdownMenuItem>
                            {(scan.status === "running" || scan.status === "queued") && (
                              <DropdownMenuItem
                                className="text-orange-400 focus:text-orange-400"
                                onClick={() => setConfirmCancel(scan.id)}
                              >
                                <StopCircle className="mr-2 h-4 w-4" />Cancel Scan
                              </DropdownMenuItem>
                            )}
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              className="text-destructive focus:text-destructive"
                              onClick={() => setConfirmDelete(scan.id)}
                            >
                              <Trash2 className="mr-2 h-4 w-4" />Delete
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <span className="text-xs text-muted-foreground">Page {page} of {totalPages} · {data?.total ?? 0} total scans</span>
          <div className="flex gap-1">
            <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>
              <ChevronLeft className="w-4 h-4" />
            </Button>
            <Button variant="outline" size="sm" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>
              <ChevronRight className="w-4 h-4" />
            </Button>
          </div>
        </div>
      )}

      {/* Confirm: single delete */}
      <ConfirmDialog
        open={!!confirmDelete}
        onOpenChange={(o) => { if (!o) setConfirmDelete(null); }}
        title="Delete Scan"
        description="This will permanently delete the scan and all its findings. This action cannot be undone."
        confirmLabel="Delete Scan"
        variant="destructive"
        loading={deleteScan.isPending}
        onConfirm={() => {
          if (confirmDelete) deleteScan.mutate(confirmDelete, { onSettled: () => setConfirmDelete(null) });
        }}
      />

      {/* Confirm: single cancel */}
      <ConfirmDialog
        open={!!confirmCancel}
        onOpenChange={(o) => { if (!o) setConfirmCancel(null); }}
        title="Cancel Scan"
        description="This will stop the running scan. Any findings discovered so far will be preserved."
        confirmLabel="Cancel Scan"
        variant="warning"
        loading={cancelScan.isPending}
        onConfirm={() => {
          if (confirmCancel) cancelScan.mutate(confirmCancel, { onSettled: () => setConfirmCancel(null) });
        }}
      />

      {/* Confirm: bulk delete */}
      <ConfirmDialog
        open={confirmBulkDelete}
        onOpenChange={setConfirmBulkDelete}
        title={`Delete ${selectedIds.size} Scans`}
        description={`This will permanently delete ${selectedIds.size} scan${selectedIds.size !== 1 ? "s" : ""} and all their findings. This action cannot be undone.`}
        confirmLabel={`Delete ${selectedIds.size} Scans`}
        variant="destructive"
        onConfirm={bulkDelete}
      />

      {/* Confirm: bulk cancel */}
      <ConfirmDialog
        open={confirmBulkCancel}
        onOpenChange={setConfirmBulkCancel}
        title="Cancel Selected Scans"
        description="This will stop all running/queued scans in your selection. Findings discovered so far will be preserved."
        confirmLabel="Cancel Scans"
        variant="warning"
        onConfirm={bulkCancel}
      />
    </div>
  );
}
