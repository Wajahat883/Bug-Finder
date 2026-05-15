import { useState, useEffect, useRef } from "react";
import { useLocation } from "wouter";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Textarea } from "@/components/ui/textarea";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import {
  Search, Filter, Download, ChevronLeft, ChevronRight,
  XCircle, AlertTriangle, CheckCircle, Trash2, Users,
  Settings, ShieldAlert, Save, Copy, X, UserCheck,
} from "lucide-react";
import { format } from "date-fns";
import { useToast } from "@/hooks/use-toast";
import { exportToExcel, exportToCsv, prepareFindingsForExport } from "@/lib/excel-export";

// ─── Types ───────────────────────────────────────────────────────────────────

interface Finding {
  id: string;
  title: string;
  severity: string;
  category: string;
  target_url: string;
  endpoint?: string;
  cvss_score?: number;
  validation_status: string;
  assignee?: string;
  created_at: string;
}

interface SavedFilter {
  id: string;
  name: string;
  filters: { search: string; severity: string };
}

// ─── Column config ────────────────────────────────────────────────────────────

const COLUMN_KEYS = ["cvss", "category", "target_url", "validation_status", "assignee", "created_at"] as const;
type ColumnKey = typeof COLUMN_KEYS[number];

const COLUMN_LABELS: Record<ColumnKey, string> = {
  cvss: "CVSS Score",
  category: "Category",
  target_url: "Target URL",
  validation_status: "Validation Status",
  assignee: "Assignee",
  created_at: "Created At",
};

function loadColumns(): Record<ColumnKey, boolean> {
  try {
    const raw = localStorage.getItem("findings_columns");
    if (raw) return { ...Object.fromEntries(COLUMN_KEYS.map(k => [k, true])), ...JSON.parse(raw) } as Record<ColumnKey, boolean>;
  } catch { /* ignore */ }
  return Object.fromEntries(COLUMN_KEYS.map(k => [k, true])) as Record<ColumnKey, boolean>;
}

function saveColumns(cols: Record<ColumnKey, boolean>) {
  localStorage.setItem("findings_columns", JSON.stringify(cols));
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-[hsl(var(--critical))] text-white",
    high: "bg-[hsl(var(--high))] text-white",
    medium: "bg-[hsl(var(--medium))] text-black",
    low: "bg-[hsl(var(--low))] text-black",
    info: "bg-[hsl(var(--info))] text-white",
  };
  return (
    <Badge className={`${colors[severity.toLowerCase()] ?? "bg-muted"} border-none uppercase text-[10px]`}>
      {severity}
    </Badge>
  );
}

function Pagination({ page, totalPages, onPage }: { page: number; totalPages: number; onPage: (p: number) => void }) {
  if (totalPages <= 1) return null;
  return (
    <div className="flex items-center justify-between pt-4">
      <span className="text-xs text-muted-foreground">Page {page} of {totalPages}</span>
      <div className="flex gap-1">
        <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          <ChevronLeft className="w-4 h-4" />
        </Button>
        {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
          const p = Math.max(1, Math.min(page - 2 + i, totalPages - 4 + i));
          return (
            <Button key={p} variant={p === page ? "default" : "outline"} size="sm" onClick={() => onPage(p)}>
              {p}
            </Button>
          );
        })}
        <Button variant="outline" size="sm" disabled={page >= totalPages} onClick={() => onPage(page + 1)}>
          <ChevronRight className="w-4 h-4" />
        </Button>
      </div>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function Findings() {
  const [, setLocation] = useLocation();
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 25;

  // Selection
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  // Dialogs / panels
  const [fpDialog, setFpDialog] = useState<Finding | null>(null);
  const [fpReason, setFpReason] = useState("");
  const [fpSuppress, setFpSuppress] = useState(false);

  // Bulk action dialogs
  const [bulkAssignOpen, setBulkAssignOpen] = useState(false);
  const [bulkAssignee, setBulkAssignee] = useState("");
  const [bulkStatusOpen, setBulkStatusOpen] = useState(false);
  const [bulkAcceptRiskOpen, setBulkAcceptRiskOpen] = useState(false);
  const [bulkAcceptJustification, setBulkAcceptJustification] = useState("");
  const [bulkDeleteOpen, setBulkDeleteOpen] = useState(false);

  // Saved filters
  const [saveFilterOpen, setSaveFilterOpen] = useState(false);
  const [saveFilterName, setSaveFilterName] = useState("");

  // Column configurator
  const [colConfigOpen, setColConfigOpen] = useState(false);
  const [columns, setColumns] = useState<Record<ColumnKey, boolean>>(loadColumns);

  const { toast } = useToast();
  const qc = useQueryClient();

  // ── Query params ──────────────────────────────────────────────────────────

  const params = new URLSearchParams({
    page: String(page),
    page_size: String(PAGE_SIZE),
    ...(search ? { search } : {}),
    ...(severityFilter !== "all" ? { severity: severityFilter } : {}),
    ...(statusFilter !== "all" ? { validation_status: statusFilter } : {}),
  });

  // ── Findings query ────────────────────────────────────────────────────────

  const { data, isLoading } = useQuery({
    queryKey: ["/api/findings", page, search, severityFilter, statusFilter],
    queryFn: () =>
      fetch(`/api/findings?${params}`, { credentials: "include" }).then(r => r.json()),
    staleTime: 10000,
  });

  const findings: Finding[] = data?.items ?? [];
  const totalPages = Math.ceil((data?.total ?? 0) / PAGE_SIZE);

  // ── Saved filters query ───────────────────────────────────────────────────

  const { data: savedFiltersData } = useQuery<SavedFilter[]>({
    queryKey: ["/api/findings/saved-filters"],
    queryFn: () =>
      fetch("/api/findings/saved-filters", { credentials: "include" }).then(r => r.json()),
    staleTime: 30000,
  });
  const savedFilters: SavedFilter[] = savedFiltersData ?? [];

  // ── Mutations ─────────────────────────────────────────────────────────────

  const markFP = useMutation({
    mutationFn: (vars: { id: string; reason: string; suppress: boolean }) =>
      fetch(`/api/findings/${vars.id}`, {
        method: "PATCH",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          validation_status: "false_positive",
          fp_reason: vars.reason,
          suppress_globally: vars.suppress,
        }),
      }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/findings"] });
      toast({
        title: "Marked as false positive",
        description: fpSuppress ? "Suppressed globally across this target." : "Updated for this finding.",
      });
      setFpDialog(null);
      setFpReason("");
      setFpSuppress(false);
    },
  });

  const bulkMutation = useMutation({
    mutationFn: (vars: { action: string; [key: string]: unknown }) =>
      fetch("/api/findings/bulk", {
        method: "PATCH",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ids: Array.from(selectedIds), ...vars }),
      }).then(r => r.json()),
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: ["/api/findings"] });
      setSelectedIds(new Set());
      const labels: Record<string, string> = {
        assign: "Findings assigned",
        status: "Status updated",
        accept_risk: "Risk accepted",
        export: "Export queued",
        delete: "Findings deleted",
      };
      toast({ title: labels[vars.action] ?? "Bulk action complete" });
    },
    onError: () => {
      toast({ title: "Bulk action failed", description: "Please try again.", variant: "destructive" });
    },
  });

  const saveFilterMutation = useMutation({
    mutationFn: (body: { name: string; resource: string; filters: object }) =>
      fetch("/api/findings/saved-filters", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/findings/saved-filters"] });
      toast({ title: "Filter saved" });
      setSaveFilterOpen(false);
      setSaveFilterName("");
    },
    onError: () => {
      toast({ title: "Failed to save filter", variant: "destructive" });
    },
  });

  const deleteFilterMutation = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/findings/saved-filters/${id}`, {
        method: "DELETE",
        credentials: "include",
      }).then(r => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/findings/saved-filters"] });
      toast({ title: "Filter deleted" });
    },
  });

  // ── Helpers ───────────────────────────────────────────────────────────────

  function toggleSelect(id: string) {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleSelectAll() {
    if (selectedIds.size === findings.length && findings.length > 0) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(findings.map(f => f.id)));
    }
  }

  function handleSearch(v: string) { setSearch(v); setPage(1); }
  function handleSeverity(v: string) { setSeverityFilter(v); setPage(1); }
  function handleStatus(v: string) { setStatusFilter(v); setPage(1); }

  function applyFilter(sf: SavedFilter) {
    setSearch(sf.filters.search ?? "");
    setSeverityFilter(sf.filters.severity ?? "all");
    setPage(1);
  }

  function toggleColumn(key: ColumnKey) {
    setColumns(prev => {
      const next = { ...prev, [key]: !prev[key] };
      saveColumns(next);
      return next;
    });
  }

  function exportCSV() { window.open(`/api/findings/export/csv?${params}`, "_blank"); }
  function exportJSON() { window.open(`/api/findings/export/json?${params}`, "_blank"); }
  function exportSARIF() { window.open(`/api/findings/export/sarif?${params}`, "_blank"); }

  function copyCurl(finding: Finding) {
    const url = `${finding.target_url}${finding.endpoint ?? ""}`;
    const cmd = `curl -X GET "${url}" -H "Content-Type: application/json"`;
    navigator.clipboard.writeText(cmd).then(() => {
      toast({ title: "Copied cURL command" });
    });
  }

  const allSelected = findings.length > 0 && selectedIds.size === findings.length;
  const someSelected = selectedIds.size > 0;

  // Visible column count for colSpan
  const visibleColCount = 3 + COLUMN_KEYS.filter(k => columns[k]).length + 1; // checkbox + severity + title + optional cols + actions

  return (
    <div className="space-y-6 pb-32">
      {/* ── Header ── */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Findings Explorer</h1>
          <p className="text-muted-foreground">Investigate and validate discovered vulnerabilities.</p>
        </div>
        <div className="flex gap-2 flex-wrap">
          <Button variant="outline" size="sm" onClick={() => {
            const rows = prepareFindingsForExport((data?.items ?? []) as Record<string, unknown>[]);
            exportToExcel(rows, "findings-export", "Findings");
          }}>
            <Download className="w-4 h-4 mr-1.5" />Excel
          </Button>
          <Button variant="outline" size="sm" onClick={() => {
            const rows = prepareFindingsForExport((data?.items ?? []) as Record<string, unknown>[]);
            exportToCsv(rows, "findings-export");
          }}>
            <Download className="w-4 h-4 mr-1.5" />CSV
          </Button>
          <Button variant="outline" size="sm" onClick={exportJSON}>
            <Download className="w-4 h-4 mr-1.5" />JSON
          </Button>
          <Button variant="outline" size="sm" onClick={exportSARIF}>
            <Download className="w-4 h-4 mr-1.5" />SARIF
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader>
          {/* ── Filter bar ── */}
          <div className="flex flex-col md:flex-row items-center gap-4">
            <div className="relative flex-1 w-full">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search findings, endpoints, or CVEs..."
                className="pl-8"
                value={search}
                onChange={(e) => handleSearch(e.target.value)}
              />
            </div>
            <div className="flex items-center gap-2 w-full md:w-auto flex-wrap">
              <Filter className="w-4 h-4 text-muted-foreground shrink-0" />
              <Select value={severityFilter} onValueChange={handleSeverity}>
                <SelectTrigger className="w-[140px]">
                  <SelectValue placeholder="Severity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Severities</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="info">Info</SelectItem>
                </SelectContent>
              </Select>
              <Select value={statusFilter} onValueChange={handleStatus}>
                <SelectTrigger className="w-[160px]">
                  <SelectValue placeholder="Validation Status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Statuses</SelectItem>
                  <SelectItem value="pending">Pending</SelectItem>
                  <SelectItem value="real">Real</SelectItem>
                  <SelectItem value="false_positive">False Positive</SelectItem>
                  <SelectItem value="informational">Informational</SelectItem>
                </SelectContent>
              </Select>

              {/* ── Saved Filters dropdown ── */}
              {savedFilters.length > 0 && (
                <Select onValueChange={(id) => {
                  const sf = savedFilters.find(f => f.id === id);
                  if (sf) applyFilter(sf);
                }}>
                  <SelectTrigger className="w-[160px]">
                    <SelectValue placeholder="Saved filters" />
                  </SelectTrigger>
                  <SelectContent>
                    {savedFilters.map(sf => (
                      <div key={sf.id} className="flex items-center justify-between px-2 py-0.5 group">
                        <SelectItem value={sf.id} className="flex-1">{sf.name}</SelectItem>
                        <button
                          className="opacity-0 group-hover:opacity-100 text-muted-foreground hover:text-destructive ml-1 shrink-0"
                          onClick={(e) => { e.stopPropagation(); deleteFilterMutation.mutate(sf.id); }}
                          title="Delete filter"
                        >
                          <X className="w-3 h-3" />
                        </button>
                      </div>
                    ))}
                  </SelectContent>
                </Select>
              )}

              {/* ── Save filter button ── */}
              <Button
                variant="outline"
                size="sm"
                className="h-9 px-2"
                onClick={() => setSaveFilterOpen(true)}
                title="Save current filters"
              >
                <Save className="w-4 h-4" />
              </Button>

              {/* ── Column configurator ── */}
              <Button
                variant="outline"
                size="sm"
                className="h-9 px-2"
                onClick={() => setColConfigOpen(true)}
                title="Configure columns"
              >
                <Settings className="w-4 h-4" />
              </Button>
            </div>
          </div>
        </CardHeader>

        <CardContent>
          <div className="rounded-md border border-border overflow-auto max-h-[600px]">
            <table className="w-full text-sm text-left">
              <thead className="text-xs text-muted-foreground uppercase bg-muted/50 border-b border-border sticky top-0 z-10">
                <tr>
                  <th className="px-4 py-3 w-10">
                    <Checkbox
                      checked={allSelected}
                      onCheckedChange={toggleSelectAll}
                      aria-label="Select all"
                    />
                  </th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Title</th>
                  {columns.cvss && <th className="px-4 py-3">CVSS</th>}
                  {columns.category && <th className="px-4 py-3">Category</th>}
                  {columns.target_url && <th className="px-4 py-3">Target / Endpoint</th>}
                  {columns.validation_status && <th className="px-4 py-3">Status</th>}
                  {columns.assignee && <th className="px-4 py-3">Assignee</th>}
                  {columns.created_at && <th className="px-4 py-3">Discovered</th>}
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {isLoading ? (
                  <tr>
                    <td colSpan={visibleColCount} className="px-4 py-8 text-center text-muted-foreground">
                      Loading findings...
                    </td>
                  </tr>
                ) : findings.length === 0 ? (
                  <tr>
                    <td colSpan={visibleColCount} className="px-4 py-16 text-center">
                      <div className="flex flex-col items-center gap-3">
                        <ShieldAlert className="w-12 h-12 text-muted-foreground/40" />
                        <div>
                          <p className="font-semibold text-foreground text-base">No findings yet</p>
                          <p className="text-muted-foreground text-sm mt-1">
                            Run your first scan to discover vulnerabilities
                          </p>
                        </div>
                        <Button size="sm" onClick={() => setLocation("/scans/new")}>
                          Start a Scan
                        </Button>
                      </div>
                    </td>
                  </tr>
                ) : (
                  findings.map((finding) => (
                    <tr
                      key={finding.id}
                      className={`hover:bg-muted/20 cursor-pointer ${selectedIds.has(finding.id) ? "bg-primary/5" : ""}`}
                      onClick={() => setLocation(`/findings/${finding.id}`)}
                    >
                      <td className="px-4 py-3 w-10" onClick={(e) => { e.stopPropagation(); toggleSelect(finding.id); }}>
                        <Checkbox
                          checked={selectedIds.has(finding.id)}
                          onCheckedChange={() => toggleSelect(finding.id)}
                          aria-label={`Select ${finding.title}`}
                        />
                      </td>
                      <td className="px-4 py-3 w-24">
                        <SeverityBadge severity={finding.severity} />
                      </td>
                      <td className="px-4 py-3">
                        <div className="font-medium text-foreground">{finding.title}</div>
                      </td>
                      {columns.cvss && (
                        <td className="px-4 py-3 font-mono text-xs">
                          {finding.cvss_score ? finding.cvss_score.toFixed(1) : "-"}
                        </td>
                      )}
                      {columns.category && (
                        <td className="px-4 py-3 text-xs text-muted-foreground">{finding.category}</td>
                      )}
                      {columns.target_url && (
                        <td className="px-4 py-3">
                          <div className="font-mono text-xs max-w-[220px] truncate">{finding.target_url}</div>
                          {finding.endpoint && (
                            <div className="font-mono text-[10px] text-muted-foreground max-w-[220px] truncate" title={finding.endpoint}>
                              {finding.endpoint}
                            </div>
                          )}
                        </td>
                      )}
                      {columns.validation_status && (
                        <td className="px-4 py-3">
                          <Badge
                            variant="outline"
                            className={`text-[10px] capitalize ${
                              finding.validation_status === "real"
                                ? "bg-red-500/10 text-red-500 border-red-500/20"
                                : finding.validation_status === "false_positive"
                                ? "bg-green-500/10 text-green-500 border-green-500/20"
                                : finding.validation_status === "informational"
                                ? "bg-blue-500/10 text-blue-500 border-blue-500/20"
                                : "bg-muted text-muted-foreground"
                            }`}
                          >
                            {finding.validation_status.replace("_", " ")}
                          </Badge>
                        </td>
                      )}
                      {columns.assignee && (
                        <td className="px-4 py-3 text-xs text-muted-foreground">
                          {finding.assignee ?? "-"}
                        </td>
                      )}
                      {columns.created_at && (
                        <td className="px-4 py-3 text-muted-foreground text-xs whitespace-nowrap">
                          {format(new Date(finding.created_at), "MMM d, yyyy")}
                        </td>
                      )}
                      <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center gap-1">
                          {/* Copy as cURL */}
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-xs text-muted-foreground hover:text-foreground h-7 px-2"
                            title="Copy as cURL"
                            onClick={() => copyCurl(finding)}
                          >
                            <Copy className="w-3.5 h-3.5" />
                          </Button>
                          {/* Mark FP */}
                          {finding.validation_status !== "false_positive" && (
                            <Button
                              variant="ghost"
                              size="sm"
                              className="text-xs text-muted-foreground hover:text-green-400 h-7 px-2"
                              onClick={() => { setFpDialog(finding); setFpReason(""); setFpSuppress(false); }}
                            >
                              <XCircle className="w-3.5 h-3.5 mr-1" />FP
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          <Pagination page={page} totalPages={totalPages} onPage={setPage} />
        </CardContent>
      </Card>

      {/* ══════════════════════════════════════════════════════════════════════
          BULK ACTION BAR — sticky bottom
      ══════════════════════════════════════════════════════════════════════ */}
      {someSelected && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 bg-card border shadow-xl rounded-xl px-4 py-3 flex items-center gap-3 z-50">
          <span className="text-sm font-medium text-foreground whitespace-nowrap">
            {selectedIds.size} selected
          </span>
          <div className="w-px h-5 bg-border" />

          {/* Assign */}
          <Button
            size="sm"
            variant="outline"
            className="h-8 text-xs"
            onClick={() => setBulkAssignOpen(true)}
          >
            <UserCheck className="w-3.5 h-3.5 mr-1.5" />Assign
          </Button>

          {/* Status */}
          <Select onValueChange={(status) => {
            bulkMutation.mutate({ action: "status", status });
          }}>
            <SelectTrigger className="h-8 text-xs w-[130px]">
              <SelectValue placeholder="Set Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="open">Open</SelectItem>
              <SelectItem value="in_progress">In Progress</SelectItem>
              <SelectItem value="resolved">Resolved</SelectItem>
              <SelectItem value="false_positive">False Positive</SelectItem>
            </SelectContent>
          </Select>

          {/* Accept Risk */}
          <Button
            size="sm"
            variant="outline"
            className="h-8 text-xs"
            onClick={() => setBulkAcceptRiskOpen(true)}
          >
            <CheckCircle className="w-3.5 h-3.5 mr-1.5" />Accept Risk
          </Button>

          {/* Export Selected */}
          <Button
            size="sm"
            variant="outline"
            className="h-8 text-xs"
            disabled={bulkMutation.isPending}
            onClick={() => bulkMutation.mutate({ action: "export" })}
          >
            <Download className="w-3.5 h-3.5 mr-1.5" />Export
          </Button>

          {/* Delete */}
          <Button
            size="sm"
            variant="outline"
            className="h-8 text-xs text-destructive border-destructive/30 hover:bg-destructive/10"
            onClick={() => setBulkDeleteOpen(true)}
          >
            <Trash2 className="w-3.5 h-3.5 mr-1.5" />Delete
          </Button>

          <div className="w-px h-5 bg-border" />

          {/* Clear */}
          <Button
            size="sm"
            variant="ghost"
            className="h-8 px-2 text-muted-foreground"
            onClick={() => setSelectedIds(new Set())}
            title="Deselect all"
          >
            <X className="w-4 h-4" />
          </Button>
        </div>
      )}

      {/* ══════════════════════════════════════════════════════════════════════
          DIALOGS
      ══════════════════════════════════════════════════════════════════════ */}

      {/* False Positive Dialog */}
      <Dialog open={!!fpDialog} onOpenChange={(o) => !o && setFpDialog(null)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <XCircle className="w-5 h-5 text-green-400" />
              Mark as False Positive
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div>
              <p className="text-sm font-medium mb-1 text-muted-foreground">Finding</p>
              <p className="text-sm font-semibold">{fpDialog?.title}</p>
            </div>
            <div>
              <label className="text-sm font-medium mb-1.5 block">
                Reason <span className="text-muted-foreground font-normal">(optional)</span>
              </label>
              <Textarea
                placeholder="Why is this a false positive? E.g. 'Test environment credential', 'Expected behavior'"
                value={fpReason}
                onChange={(e) => setFpReason(e.target.value)}
                rows={3}
                className="resize-none"
              />
            </div>
            <div className="flex items-start gap-3 p-3 rounded-md border border-orange-500/20 bg-orange-500/5">
              <Checkbox
                id="suppress"
                checked={fpSuppress}
                onCheckedChange={(v) => setFpSuppress(!!v)}
                className="mt-0.5"
              />
              <div>
                <label htmlFor="suppress" className="text-sm font-medium cursor-pointer flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-orange-400" />
                  Suppress globally for this target
                </label>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Future scans of this target will automatically suppress the same finding (matched by title + endpoint).
                </p>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setFpDialog(null)}>Cancel</Button>
            <Button
              className="bg-green-600 hover:bg-green-700 text-white"
              disabled={markFP.isPending}
              onClick={() =>
                fpDialog && markFP.mutate({ id: fpDialog.id, reason: fpReason, suppress: fpSuppress })
              }
            >
              {markFP.isPending ? "Saving…" : "Confirm False Positive"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Bulk Assign Dialog */}
      <Dialog open={bulkAssignOpen} onOpenChange={setBulkAssignOpen}>
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <UserCheck className="w-5 h-5" />
              Assign Findings
            </DialogTitle>
          </DialogHeader>
          <div className="py-2 space-y-3">
            <p className="text-sm text-muted-foreground">
              Assign {selectedIds.size} finding{selectedIds.size !== 1 ? "s" : ""} to:
            </p>
            <Input
              placeholder="Assignee ID or username"
              value={bulkAssignee}
              onChange={(e) => setBulkAssignee(e.target.value)}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setBulkAssignOpen(false)}>Cancel</Button>
            <Button
              disabled={!bulkAssignee.trim() || bulkMutation.isPending}
              onClick={() => {
                bulkMutation.mutate({ action: "assign", assignee_id: bulkAssignee.trim() });
                setBulkAssignOpen(false);
                setBulkAssignee("");
              }}
            >
              Assign
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Bulk Accept Risk Dialog */}
      <Dialog open={bulkAcceptRiskOpen} onOpenChange={setBulkAcceptRiskOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <CheckCircle className="w-5 h-5" />
              Accept Risk
            </DialogTitle>
          </DialogHeader>
          <div className="py-2 space-y-3">
            <p className="text-sm text-muted-foreground">
              Accept risk for {selectedIds.size} finding{selectedIds.size !== 1 ? "s" : ""}. Provide a justification:
            </p>
            <Textarea
              placeholder="Justification for accepting this risk..."
              value={bulkAcceptJustification}
              onChange={(e) => setBulkAcceptJustification(e.target.value)}
              rows={4}
              className="resize-none"
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setBulkAcceptRiskOpen(false)}>Cancel</Button>
            <Button
              disabled={!bulkAcceptJustification.trim() || bulkMutation.isPending}
              onClick={() => {
                bulkMutation.mutate({ action: "accept_risk", justification: bulkAcceptJustification.trim() });
                setBulkAcceptRiskOpen(false);
                setBulkAcceptJustification("");
              }}
            >
              Accept Risk
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Bulk Delete Confirm Dialog */}
      <Dialog open={bulkDeleteOpen} onOpenChange={setBulkDeleteOpen}>
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Trash2 className="w-5 h-5 text-destructive" />
              Delete Findings
            </DialogTitle>
          </DialogHeader>
          <div className="py-2">
            <p className="text-sm text-muted-foreground">
              Are you sure you want to delete{" "}
              <span className="font-semibold text-foreground">{selectedIds.size}</span>{" "}
              finding{selectedIds.size !== 1 ? "s" : ""}? This action cannot be undone.
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setBulkDeleteOpen(false)}>Cancel</Button>
            <Button
              variant="destructive"
              disabled={bulkMutation.isPending}
              onClick={() => {
                bulkMutation.mutate({ action: "delete" });
                setBulkDeleteOpen(false);
              }}
            >
              {bulkMutation.isPending ? "Deleting…" : `Delete ${selectedIds.size} Finding${selectedIds.size !== 1 ? "s" : ""}`}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Save Filter Dialog */}
      <Dialog open={saveFilterOpen} onOpenChange={setSaveFilterOpen}>
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Save className="w-4 h-4" />
              Save Current Filters
            </DialogTitle>
          </DialogHeader>
          <div className="py-2 space-y-3">
            <p className="text-sm text-muted-foreground">
              Saving: severity=<strong>{severityFilter}</strong>
              {search && <>, search=<strong>{search}</strong></>}
            </p>
            <Input
              placeholder="Filter preset name"
              value={saveFilterName}
              onChange={(e) => setSaveFilterName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && saveFilterName.trim()) {
                  saveFilterMutation.mutate({
                    name: saveFilterName.trim(),
                    resource: "findings",
                    filters: { search, severity: severityFilter },
                  });
                }
              }}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setSaveFilterOpen(false)}>Cancel</Button>
            <Button
              disabled={!saveFilterName.trim() || saveFilterMutation.isPending}
              onClick={() =>
                saveFilterMutation.mutate({
                  name: saveFilterName.trim(),
                  resource: "findings",
                  filters: { search, severity: severityFilter },
                })
              }
            >
              {saveFilterMutation.isPending ? "Saving…" : "Save Filter"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Column Configurator Dialog */}
      <Dialog open={colConfigOpen} onOpenChange={setColConfigOpen}>
        <DialogContent className="sm:max-w-xs">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Settings className="w-4 h-4" />
              Configure Columns
            </DialogTitle>
          </DialogHeader>
          <div className="py-2 space-y-3">
            {COLUMN_KEYS.map((key) => (
              <div key={key} className="flex items-center gap-3">
                <Checkbox
                  id={`col-${key}`}
                  checked={columns[key]}
                  onCheckedChange={() => toggleColumn(key)}
                />
                <label htmlFor={`col-${key}`} className="text-sm cursor-pointer select-none">
                  {COLUMN_LABELS[key]}
                </label>
              </div>
            ))}
          </div>
          <DialogFooter>
            <Button onClick={() => setColConfigOpen(false)}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
