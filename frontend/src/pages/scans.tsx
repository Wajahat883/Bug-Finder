import { useState } from "react";
import { useLocation } from "wouter";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Search, Plus, Trash2, Eye, MoreHorizontal, Download, StopCircle, ChevronLeft, ChevronRight } from "lucide-react";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { format } from "date-fns";
import { useToast } from "@/hooks/use-toast";

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

function SeverityDot({ color, count }: { color: string; count: number }) {
  if (!count) return null;
  return (
    <span className="flex items-center gap-1 text-[11px] font-mono" style={{ color }}>
      <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: color }} />
      {count}
    </span>
  );
}

const PAGE_SIZE = 20;

export default function Scans() {
  const [, setLocation] = useLocation();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [page, setPage] = useState(1);
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
      fetch(`/api/scan-jobs/${id}`, { method: "DELETE", credentials: "include" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["/api/scan-jobs"] }),
  });

  const cancelScan = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/scan-jobs/${id}/cancel`, { method: "POST", credentials: "include" }).then(r => r.json()),
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: ["/api/scan-jobs"] });
      toast({ title: "Scan cancelled", description: `Scan ${id.slice(0, 8)} has been cancelled.` });
    },
  });

  function exportCSV() {
    window.open(`/api/scan-jobs/export/csv?${params}`, "_blank");
  }
  function exportJSON() {
    window.open(`/api/scan-jobs/export/json?${params}`, "_blank");
  }

  function handleSearch(v: string) { setSearch(v); setPage(1); }
  function handleStatus(v: string) { setStatusFilter(v); setPage(1); }

  const statuses = ["all", "queued", "running", "completed", "failed", "cancelled"];

  return (
    <div className="space-y-4">
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
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 px-3 py-2 rounded-md text-sm flex-1 max-w-xs"
          style={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))" }}>
          <Search className="w-3.5 h-3.5 flex-shrink-0" style={{ color: "hsl(var(--muted-foreground))" }} />
          <input
            type="text"
            placeholder="Search target or ID..."
            className="bg-transparent border-none outline-none text-sm w-full"
            value={search}
            onChange={(e) => handleSearch(e.target.value)}
          />
        </div>
        <div className="flex items-center gap-1.5">
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

      {/* Table */}
      <div className="rounded-lg border overflow-hidden"
        style={{ background: "hsl(var(--card))", borderColor: "hsl(var(--border))" }}>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-[10px] font-mono font-semibold uppercase tracking-wider border-b"
              style={{ color: "hsl(var(--muted-foreground))", borderColor: "hsl(var(--border))", background: "hsl(var(--sidebar))" }}>
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
            {isLoading ? (
              <tr><td colSpan={7} className="px-4 py-10 text-center text-sm" style={{ color: "hsl(var(--muted-foreground))" }}>Loading scans...</td></tr>
            ) : scans.length === 0 ? (
              <tr><td colSpan={7} className="px-4 py-10 text-center text-sm" style={{ color: "hsl(var(--muted-foreground))" }}>No scans found.</td></tr>
            ) : (
              scans.map((scan) => (
                <tr key={scan.id} className="transition-colors cursor-pointer"
                  onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = "hsl(var(--muted))"; }}
                  onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = ""; }}
                  onClick={() => setLocation(`/scans/${scan.id}`)}>
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
                      <div className="flex items-center gap-2.5">
                        <SeverityDot color="#f87171" count={scan.critical_count} />
                        <SeverityDot color="#fb923c" count={scan.high_count} />
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
                        {(scan.status === "running" || scan.status === "queued") && (
                          <DropdownMenuItem
                            className="text-orange-400 focus:text-orange-400"
                            onClick={() => cancelScan.mutate(scan.id)}
                          >
                            <StopCircle className="mr-2 h-4 w-4" />Cancel Scan
                          </DropdownMenuItem>
                        )}
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          className="text-destructive focus:text-destructive"
                          onClick={() => { if (confirm("Delete this scan?")) deleteScan.mutate(scan.id); }}
                        >
                          <Trash2 className="mr-2 h-4 w-4" />Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

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
    </div>
  );
}
