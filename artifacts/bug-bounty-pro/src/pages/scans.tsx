import { useState } from "react";
import { useListScanJobs, useDeleteScanJob } from "@workspace/api-client-react";
import { useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Search, Plus, Trash2, Eye, MoreHorizontal } from "lucide-react";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { format } from "date-fns";

function StatusBadge({ status }: { status: string }) {
  const cfg: Record<string, { label: string; bg: string; color: string; border: string }> = {
    queued:    { label: "QUEUED",    bg: "transparent",          color: "#94a3b8", border: "rgba(148,163,184,0.3)" },
    running:   { label: "RUNNING",   bg: "rgba(34,211,238,0.15)", color: "#22d3ee", border: "rgba(34,211,238,0.35)" },
    completed: { label: "COMPLETED", bg: "rgba(74,222,128,0.15)", color: "#4ade80", border: "rgba(74,222,128,0.35)" },
    failed:    { label: "FAILED",    bg: "rgba(248,113,113,0.15)",color: "#f87171", border: "rgba(248,113,113,0.35)" },
    cancelled: { label: "CANCELLED", bg: "transparent",          color: "#94a3b8", border: "rgba(148,163,184,0.3)" },
  };
  const c = cfg[status.toLowerCase()] ?? cfg.queued;
  return (
    <span
      className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-sm"
      style={{ background: c.bg, color: c.color, border: `1px solid ${c.border}` }}
    >
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

export default function Scans() {
  const [, setLocation] = useLocation();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");

  const { data: raw, isLoading } = useListScanJobs({
    search: search || undefined,
    status: statusFilter !== "all" ? (statusFilter as any) : undefined,
  });

  const scans: any[] = Array.isArray(raw) ? raw : (raw as any)?.items ?? [];

  const deleteScan = useDeleteScanJob();

  const filtered = scans.filter((s) => {
    const matchSearch = !search || s.target_url?.toLowerCase().includes(search.toLowerCase());
    const matchStatus = statusFilter === "all" || s.status === statusFilter;
    return matchSearch && matchStatus;
  });

  const statuses = ["all", "queued", "running", "completed", "failed", "cancelled"];

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
        <Button
          onClick={() => setLocation("/scans/new")}
          className="text-sm font-semibold"
          style={{
            background: "linear-gradient(135deg, #7c3aed, #a855f7)",
            color: "white",
            border: "none",
          }}
        >
          <Plus className="w-4 h-4 mr-1.5" />
          NEW SCAN
        </Button>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        {/* Search */}
        <div
          className="flex items-center gap-2 px-3 py-2 rounded-md text-sm flex-1 max-w-xs"
          style={{
            background: "hsl(var(--card))",
            border: "1px solid hsl(var(--border))",
          }}
        >
          <Search className="w-3.5 h-3.5 flex-shrink-0" style={{ color: "hsl(var(--muted-foreground))" }} />
          <input
            type="text"
            placeholder="Search target or ID..."
            className="bg-transparent border-none outline-none text-sm w-full"
            style={{ color: "hsl(var(--foreground))" }}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        {/* Status filter pills */}
        <div className="flex items-center gap-1.5">
          {statuses.map((s) => {
            const active = statusFilter === s;
            return (
              <button
                key={s}
                onClick={() => setStatusFilter(s)}
                className="text-[10px] font-mono font-semibold px-2.5 py-1 rounded-sm capitalize transition-all"
                style={
                  active
                    ? { background: "hsl(var(--primary))", color: "white" }
                    : {
                        background: "hsl(var(--card))",
                        color: "hsl(var(--muted-foreground))",
                        border: "1px solid hsl(var(--border))",
                      }
                }
              >
                {s === "all" ? "All" : s}
              </button>
            );
          })}
        </div>
      </div>

      {/* Table */}
      <div
        className="rounded-lg border overflow-hidden"
        style={{ background: "hsl(var(--card))", borderColor: "hsl(var(--border))" }}
      >
        <table className="w-full text-sm">
          <thead>
            <tr
              className="text-[10px] font-mono font-semibold uppercase tracking-wider border-b"
              style={{
                color: "hsl(var(--muted-foreground))",
                borderColor: "hsl(var(--border))",
                background: "hsl(var(--sidebar))",
              }}
            >
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
              <tr>
                <td colSpan={7} className="px-4 py-10 text-center text-sm" style={{ color: "hsl(var(--muted-foreground))" }}>
                  Loading scans...
                </td>
              </tr>
            ) : filtered.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-10 text-center text-sm" style={{ color: "hsl(var(--muted-foreground))" }}>
                  No scans found.
                </td>
              </tr>
            ) : (
              filtered.map((scan) => (
                <tr
                  key={scan.id}
                  className="transition-colors cursor-pointer"
                  style={{ borderColor: "hsl(var(--border))" }}
                  onMouseEnter={(e) => {
                    (e.currentTarget as HTMLElement).style.background = "hsl(var(--muted))";
                  }}
                  onMouseLeave={(e) => {
                    (e.currentTarget as HTMLElement).style.background = "";
                  }}
                  onClick={() => setLocation(`/scans/${scan.id}`)}
                >
                  {/* ID */}
                  <td className="px-4 py-3">
                    <span className="font-mono text-xs" style={{ color: "#22d3ee" }}>
                      {String(scan.id).slice(0, 8)}
                    </span>
                  </td>
                  {/* Target */}
                  <td className="px-4 py-3">
                    <span className="font-mono text-xs" style={{ color: "hsl(var(--foreground))" }}>
                      {scan.target_url}
                    </span>
                  </td>
                  {/* Status */}
                  <td className="px-4 py-3">
                    <StatusBadge status={scan.status} />
                  </td>
                  {/* Profile */}
                  <td className="px-4 py-3">
                    <span className="text-[10px] font-mono uppercase tracking-wider" style={{ color: "hsl(var(--muted-foreground))" }}>
                      {scan.scan_profile}
                    </span>
                  </td>
                  {/* Findings */}
                  <td className="px-4 py-3">
                    {scan.findings_count > 0 ? (
                      <div className="flex items-center gap-2.5">
                        <SeverityDot color="#f87171" count={scan.critical_count} />
                        <SeverityDot color="#fb923c" count={scan.high_count} />
                        <span className="text-xs font-mono" style={{ color: "hsl(var(--muted-foreground))" }}>
                          {scan.findings_count} total
                        </span>
                      </div>
                    ) : (
                      <span className="text-xs font-mono" style={{ color: "hsl(var(--muted-foreground))" }}>
                        {scan.status === "completed" ? "0 total" : "—"}
                      </span>
                    )}
                  </td>
                  {/* Started */}
                  <td className="px-4 py-3">
                    <span className="text-xs font-mono" style={{ color: "hsl(var(--muted-foreground))" }}>
                      {format(new Date(scan.created_at), "M/d/yyyy, h:mm:ss aa")}
                    </span>
                  </td>
                  {/* Actions */}
                  <td className="px-4 py-3 text-right" onClick={(e) => e.stopPropagation()}>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" className="h-7 w-7 p-0">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => setLocation(`/scans/${scan.id}`)}>
                          <Eye className="mr-2 h-4 w-4" />
                          View Details
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          className="text-destructive focus:text-destructive"
                          onClick={() => {
                            if (confirm("Delete this scan?")) deleteScan.mutate({ id: scan.id });
                          }}
                        >
                          <Trash2 className="mr-2 h-4 w-4" />
                          Delete
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
    </div>
  );
}
