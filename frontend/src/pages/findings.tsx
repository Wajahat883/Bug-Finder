import { useState } from "react";
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
} from "lucide-react";
import { format } from "date-fns";
import { useToast } from "@/hooks/use-toast";

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

interface Finding {
  id: string;
  title: string;
  severity: string;
  category: string;
  target_url: string;
  endpoint: string;
  cvss_score?: number;
  validation_status: string;
  created_at: string;
}

export default function Findings() {
  const [, setLocation] = useLocation();
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 25;

  // Bulk selection state
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const { toast } = useToast();
  const qc = useQueryClient();

  // FP dialog state
  const [fpDialog, setFpDialog] = useState<Finding | null>(null);
  const [fpReason, setFpReason] = useState("");
  const [fpSuppress, setFpSuppress] = useState(false);

  const params = new URLSearchParams({
    page: String(page),
    page_size: String(PAGE_SIZE),
    ...(search ? { search } : {}),
    ...(severityFilter !== "all" ? { severity: severityFilter } : {}),
    ...(statusFilter !== "all" ? { validation_status: statusFilter } : {}),
  });

  const { data, isLoading } = useQuery({
    queryKey: ["/api/findings", page, search, severityFilter, statusFilter],
    queryFn: () =>
      fetch(`/api/findings?${params}`, { credentials: "include" }).then(r => r.json()),
    staleTime: 10000,
  });

  const findings: Finding[] = data?.items ?? [];
  const totalPages = Math.ceil((data?.total ?? 0) / PAGE_SIZE);

  // Mark single as FP
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
      toast({ title: "Marked as false positive", description: fpSuppress ? "Suppressed globally across this target." : "Updated for this finding." });
      setFpDialog(null);
      setFpReason("");
      setFpSuppress(false);
    },
  });

  // Bulk action mutation
  const bulkAction = useMutation({
    mutationFn: (vars: { action: string; value?: string }) =>
      fetch("/api/findings/bulk", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ids: Array.from(selected), action: vars.action, value: vars.value }),
      }).then(r => r.json()),
    onSuccess: (data, vars) => {
      qc.invalidateQueries({ queryKey: ["/api/findings"] });
      setSelected(new Set());
      const labels: Record<string, string> = {
        mark_fp: "Marked as false positive",
        mark_real: "Marked as real",
        mark_informational: "Marked as informational",
        delete: "Deleted",
      };
      toast({
        title: labels[vars.action] ?? "Bulk action complete",
        description: `${data?.affected ?? selected.size} finding(s) updated.`,
      });
    },
    onError: () => {
      toast({ title: "Bulk action failed", description: "Please try again.", variant: "destructive" });
    },
  });

  function toggleSelect(id: string) {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleSelectAll() {
    if (selected.size === findings.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(findings.map(f => f.id)));
    }
  }

  function exportCSV() { window.open(`/api/findings/export/csv?${params}`, "_blank"); }
  function exportJSON() { window.open(`/api/findings/export/json?${params}`, "_blank"); }
  function exportSARIF() { window.open(`/api/findings/export/sarif?${params}`, "_blank"); }

  function handleSearch(v: string) { setSearch(v); setPage(1); }
  function handleSeverity(v: string) { setSeverityFilter(v); setPage(1); }
  function handleStatus(v: string) { setStatusFilter(v); setPage(1); }

  const allSelected = findings.length > 0 && selected.size === findings.length;
  const someSelected = selected.size > 0;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Findings Explorer</h1>
          <p className="text-muted-foreground">Investigate and validate discovered vulnerabilities.</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={exportCSV}>
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
            <div className="flex items-center gap-2 w-full md:w-auto">
              <Filter className="w-4 h-4 text-muted-foreground" />
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
            </div>
          </div>

          {/* Bulk action toolbar — only visible when items are selected */}
          {someSelected && (
            <div className="flex items-center gap-3 p-3 rounded-md bg-primary/10 border border-primary/20 mt-2">
              <span className="text-sm font-medium text-primary">
                {selected.size} finding{selected.size !== 1 ? "s" : ""} selected
              </span>
              <div className="flex gap-2 ml-auto">
                <Button
                  size="sm"
                  variant="outline"
                  className="text-green-400 border-green-400/30 hover:bg-green-400/10 h-7 text-xs"
                  disabled={bulkAction.isPending}
                  onClick={() => bulkAction.mutate({ action: "mark_fp" })}
                >
                  <XCircle className="w-3.5 h-3.5 mr-1" />Mark FP
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="text-red-400 border-red-400/30 hover:bg-red-400/10 h-7 text-xs"
                  disabled={bulkAction.isPending}
                  onClick={() => bulkAction.mutate({ action: "mark_real" })}
                >
                  <CheckCircle className="w-3.5 h-3.5 mr-1" />Mark Real
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="text-blue-400 border-blue-400/30 hover:bg-blue-400/10 h-7 text-xs"
                  disabled={bulkAction.isPending}
                  onClick={() => bulkAction.mutate({ action: "mark_informational" })}
                >
                  <Users className="w-3.5 h-3.5 mr-1" />Informational
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="text-destructive border-destructive/30 hover:bg-destructive/10 h-7 text-xs"
                  disabled={bulkAction.isPending}
                  onClick={() => {
                    if (window.confirm(`Delete ${selected.size} finding(s)? This cannot be undone.`)) {
                      bulkAction.mutate({ action: "delete" });
                    }
                  }}
                >
                  <Trash2 className="w-3.5 h-3.5 mr-1" />Delete
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-7 text-xs text-muted-foreground"
                  onClick={() => setSelected(new Set())}
                >
                  Clear
                </Button>
              </div>
            </div>
          )}
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
                  <th className="px-4 py-3">Target / Endpoint</th>
                  <th className="px-4 py-3">CVSS</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Discovered</th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {isLoading ? (
                  <tr><td colSpan={8} className="px-4 py-8 text-center text-muted-foreground">Loading findings...</td></tr>
                ) : findings.length === 0 ? (
                  <tr><td colSpan={8} className="px-4 py-8 text-center text-muted-foreground">No findings matching your criteria.</td></tr>
                ) : (
                  findings.map((finding) => (
                    <tr
                      key={finding.id}
                      className={`hover:bg-muted/20 cursor-pointer ${selected.has(finding.id) ? "bg-primary/5" : ""}`}
                      onClick={() => setLocation(`/findings/${finding.id}`)}
                    >
                      <td className="px-4 py-3 w-10" onClick={(e) => { e.stopPropagation(); toggleSelect(finding.id); }}>
                        <Checkbox
                          checked={selected.has(finding.id)}
                          onCheckedChange={() => toggleSelect(finding.id)}
                          aria-label={`Select ${finding.title}`}
                        />
                      </td>
                      <td className="px-4 py-3 w-24"><SeverityBadge severity={finding.severity} /></td>
                      <td className="px-4 py-3">
                        <div className="font-medium text-foreground">{finding.title}</div>
                        <div className="text-xs text-muted-foreground">{finding.category}</div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="font-mono text-xs max-w-[300px] truncate">{finding.target_url}</div>
                        <div className="font-mono text-[10px] text-muted-foreground max-w-[300px] truncate" title={finding.endpoint}>{finding.endpoint}</div>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs">{finding.cvss_score ? finding.cvss_score.toFixed(1) : "-"}</td>
                      <td className="px-4 py-3">
                        <Badge variant="outline" className={`text-[10px] capitalize ${
                          finding.validation_status === "real" ? "bg-red-500/10 text-red-500 border-red-500/20" :
                          finding.validation_status === "false_positive" ? "bg-green-500/10 text-green-500 border-green-500/20" :
                          finding.validation_status === "informational" ? "bg-blue-500/10 text-blue-500 border-blue-500/20" :
                          "bg-muted text-muted-foreground"
                        }`}>
                          {finding.validation_status.replace("_", " ")}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 text-muted-foreground text-xs whitespace-nowrap">
                        {format(new Date(finding.created_at), "MMM d, yyyy")}
                      </td>
                      <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                        {finding.validation_status !== "false_positive" && (
                          <Button
                            variant="ghost" size="sm"
                            className="text-xs text-muted-foreground hover:text-green-400 h-7 px-2"
                            onClick={() => { setFpDialog(finding); setFpReason(""); setFpSuppress(false); }}
                          >
                            <XCircle className="w-3.5 h-3.5 mr-1" />FP
                          </Button>
                        )}
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
              <label className="text-sm font-medium mb-1.5 block">Reason <span className="text-muted-foreground font-normal">(optional)</span></label>
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
              onClick={() => fpDialog && markFP.mutate({ id: fpDialog.id, reason: fpReason, suppress: fpSuppress })}
            >
              {markFP.isPending ? "Saving…" : "Confirm False Positive"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
