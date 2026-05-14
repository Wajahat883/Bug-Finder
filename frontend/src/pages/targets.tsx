import { useState, useRef } from "react";
import { Link, useLocation } from "wouter";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Search, Globe, ShieldAlert, ChevronUp, ChevronDown, ChevronsUpDown,
  Upload, Tag, Play, Cpu, X, Plus, AlertTriangle, Target as TargetIcon,
  Trash2,
} from "lucide-react";
import { TableSkeleton } from "@/components/loading-skeleton";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { format, differenceInDays } from "date-fns";
import { useToast } from "@/hooks/use-toast";

// ── Types ────────────────────────────────────────────────────────────────────

interface Target {
  id: string;
  url: string;
  domain: string;
  last_scanned: string | null;
  total_scans: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  risk_score: number;
  status: string;
  tags: string[];
  tech_stack: string[];
  subdomains: string[];
  risk_history: Array<{ score: number; date: string }>;
}

interface TargetsResponse {
  items: Target[];
  total: number;
  all_tags: string[];
}

// ── Sparkline ────────────────────────────────────────────────────────────────

function RiskSparkline({ history }: { history: Array<{ score: number }> }) {
  if (history.length < 2) return <span className="text-xs text-muted-foreground">—</span>;
  const w = 60, h = 24;
  const scores = history.map((h) => h.score);
  const max = Math.max(...scores, 1);
  const min = Math.min(...scores);
  const range = max - min || 1;
  const pts = scores.map((v, i) => {
    const x = (i / (scores.length - 1)) * w;
    const y = h - ((v - min) / range) * (h - 4) - 2;
    return `${x},${y}`;
  });
  const last = scores[scores.length - 1];
  const prev = scores[scores.length - 2];
  const color = last > prev ? "#ef4444" : last < prev ? "#22c55e" : "#6b7280";
  return (
    <svg width={w} height={h} className="overflow-visible">
      <polyline points={pts.join(" ")} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={pts[pts.length - 1].split(",")[0]} cy={pts[pts.length - 1].split(",")[1]} r="2.5" fill={color} />
    </svg>
  );
}

// ── Health badge ─────────────────────────────────────────────────────────────

function HealthBadge({ lastScanned }: { lastScanned: string | null }) {
  if (!lastScanned) return <Badge variant="outline" className="text-[10px] px-1.5 text-muted-foreground">Never</Badge>;
  const days = differenceInDays(new Date(), new Date(lastScanned));
  if (days < 7) return <Badge variant="outline" className="text-[10px] px-1.5 bg-green-500/10 text-green-500 border-green-500/30">Fresh</Badge>;
  if (days < 30) return <Badge variant="outline" className="text-[10px] px-1.5 bg-yellow-500/10 text-yellow-500 border-yellow-500/30">Stale</Badge>;
  return <Badge variant="outline" className="text-[10px] px-1.5 bg-red-500/10 text-red-500 border-red-500/30">Outdated</Badge>;
}

// ── Tag pill ─────────────────────────────────────────────────────────────────

const TAG_COLORS: Record<string, string> = {
  production: "bg-red-500/15 text-red-400 border-red-500/25",
  staging: "bg-yellow-500/15 text-yellow-400 border-yellow-500/25",
  "in-scope": "bg-green-500/15 text-green-400 border-green-500/25",
  "out-of-scope": "bg-gray-500/15 text-gray-400 border-gray-500/25",
  dev: "bg-blue-500/15 text-blue-400 border-blue-500/25",
};

function TagPill({ tag, onRemove }: { tag: string; onRemove?: () => void }) {
  const cls = TAG_COLORS[tag] ?? "bg-violet-500/15 text-violet-400 border-violet-500/25";
  return (
    <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium border ${cls}`}>
      {tag}
      {onRemove && <button onClick={onRemove} className="hover:opacity-70"><X className="w-2.5 h-2.5" /></button>}
    </span>
  );
}

// ── Tech badge ───────────────────────────────────────────────────────────────

function TechBadge({ tech }: { tech: string }) {
  return (
    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono border bg-muted/50 text-muted-foreground">
      <Cpu className="w-2.5 h-2.5" />{tech}
    </span>
  );
}

// ── Sort header ──────────────────────────────────────────────────────────────

function SortTh({ label, field, current, dir, onClick }: {
  label: string; field: string; current: string; dir: "asc" | "desc"; onClick: (f: string) => void;
}) {
  const active = current === field;
  return (
    <th className="px-4 py-3 cursor-pointer select-none whitespace-nowrap" onClick={() => onClick(field)}>
      <span className="flex items-center gap-1 text-xs text-muted-foreground uppercase font-semibold">
        {label}
        {active ? (dir === "asc" ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />) : <ChevronsUpDown className="w-3 h-3 opacity-40" />}
      </span>
    </th>
  );
}

// ── Tag editor dialog ─────────────────────────────────────────────────────────

const PRESET_TAGS = ["production", "staging", "in-scope", "out-of-scope", "dev", "api", "mobile", "legacy"];

function TagEditorDialog({ target, onClose }: { target: Target; onClose: () => void }) {
  const [tags, setTags] = useState<string[]>(target.tags);
  const [custom, setCustom] = useState("");
  const { toast } = useToast();
  const qc = useQueryClient();

  const mutation = useMutation({
    mutationFn: (newTags: string[]) =>
      fetch(`/api/targets/${target.id}/tags`, {
        method: "PATCH", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tags: newTags }),
      }).then((r) => r.json()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/targets"] });
      toast({ title: "Tags updated" });
      onClose();
    },
  });

  function addTag(tag: string) {
    const t = tag.trim().toLowerCase();
    if (t && !tags.includes(t)) setTags([...tags, t]);
  }

  return (
    <DialogContent>
      <DialogHeader><DialogTitle>Edit Tags — {target.domain}</DialogTitle></DialogHeader>
      <div className="space-y-4">
        <div>
          <p className="text-xs text-muted-foreground mb-2">Current tags:</p>
          <div className="flex flex-wrap gap-1.5 min-h-[32px] p-2 border rounded-md bg-muted/20">
            {tags.length === 0 && <span className="text-xs text-muted-foreground">No tags</span>}
            {tags.map((t) => <TagPill key={t} tag={t} onRemove={() => setTags(tags.filter((x) => x !== t))} />)}
          </div>
        </div>
        <div>
          <p className="text-xs text-muted-foreground mb-2">Quick add:</p>
          <div className="flex flex-wrap gap-1.5">
            {PRESET_TAGS.filter((t) => !tags.includes(t)).map((t) => (
              <button key={t} onClick={() => addTag(t)}
                className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs border border-dashed hover:bg-accent transition-colors">
                <Plus className="w-3 h-3" />{t}
              </button>
            ))}
          </div>
        </div>
        <div className="flex gap-2">
          <Input placeholder="Custom tag…" value={custom} onChange={(e) => setCustom(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") { addTag(custom); setCustom(""); } }}
            className="h-8 text-sm" />
          <Button size="sm" variant="outline" onClick={() => { addTag(custom); setCustom(""); }}>Add</Button>
        </div>
      </div>
      <DialogFooter>
        <Button variant="outline" onClick={onClose}>Cancel</Button>
        <Button onClick={() => mutation.mutate(tags)} disabled={mutation.isPending}>
          {mutation.isPending ? "Saving…" : "Save Tags"}
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}

// ── Bulk import dialog ───────────────────────────────────────────────────────

function BulkImportDialog({ onClose }: { onClose: () => void }) {
  const [text, setText] = useState("");
  const [tags, setTags] = useState<string[]>([]);
  const [tagInput, setTagInput] = useState("");
  const [result, setResult] = useState<{ imported: number; skipped: number } | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const { toast } = useToast();
  const qc = useQueryClient();

  const mutation = useMutation({
    mutationFn: (payload: { urls: string[]; tags: string[] }) =>
      fetch("/api/targets/bulk-import", {
        method: "POST", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      }).then((r) => r.json()),
    onSuccess: (data: { imported: number; skipped: number }) => {
      setResult(data);
      qc.invalidateQueries({ queryKey: ["/api/targets"] });
      toast({ title: `Imported ${data.imported} targets`, description: `${data.skipped} skipped (already exist or invalid)` });
    },
  });

  function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => setText(String(ev.target?.result ?? ""));
    reader.readAsText(file);
  }

  function handleImport() {
    const urls = text.split(/[\n,]+/).map((u) => u.trim()).filter(Boolean);
    mutation.mutate({ urls, tags });
  }

  return (
    <DialogContent className="max-w-lg">
      <DialogHeader><DialogTitle className="flex items-center gap-2"><Upload className="w-4 h-4" />Bulk Import Targets</DialogTitle></DialogHeader>
      <div className="space-y-4">
        {result ? (
          <div className="text-center py-4 space-y-2">
            <div className="text-3xl font-bold text-green-500">{result.imported}</div>
            <div className="text-sm text-muted-foreground">targets imported ({result.skipped} skipped)</div>
            <Button onClick={onClose} className="mt-2">Done</Button>
          </div>
        ) : (
          <>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-sm font-medium">URLs / Domains</label>
                <button onClick={() => fileRef.current?.click()} className="text-xs text-primary hover:underline flex items-center gap-1">
                  <Upload className="w-3 h-3" /> Upload CSV / TXT
                </button>
                <input ref={fileRef} type="file" accept=".csv,.txt" className="hidden" onChange={handleFile} />
              </div>
              <textarea
                className="w-full h-36 text-sm border rounded-md p-3 bg-background font-mono resize-none focus:outline-none focus:ring-1 focus:ring-primary"
                placeholder={"https://example.com\nhttps://api.example.com\nsub.domain.com"}
                value={text}
                onChange={(e) => setText(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">One URL per line, or comma-separated. http:// prefix optional.</p>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">Apply tags to all imported targets</label>
              <div className="flex flex-wrap gap-1.5 min-h-[32px] p-2 border rounded-md bg-muted/20">
                {tags.map((t) => <TagPill key={t} tag={t} onRemove={() => setTags(tags.filter((x) => x !== t))} />)}
              </div>
              <div className="flex gap-2">
                {PRESET_TAGS.filter((t) => !tags.includes(t)).map((t) => (
                  <button key={t} onClick={() => setTags([...tags, t])}
                    className="text-xs px-2 py-1 rounded border border-dashed hover:bg-accent">{t}</button>
                ))}
              </div>
              <div className="flex gap-2">
                <Input placeholder="Custom tag…" value={tagInput} onChange={(e) => setTagInput(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter" && tagInput.trim()) { setTags([...tags, tagInput.trim()]); setTagInput(""); } }}
                  className="h-8 text-sm" />
                <Button size="sm" variant="outline" onClick={() => { if (tagInput.trim()) { setTags([...tags, tagInput.trim()]); setTagInput(""); } }}>Add</Button>
              </div>
            </div>
          </>
        )}
      </div>
      {!result && (
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={handleImport} disabled={mutation.isPending || !text.trim()}>
            {mutation.isPending ? "Importing…" : `Import ${text.split(/[\n,]+/).filter((u) => u.trim()).length} targets`}
          </Button>
        </DialogFooter>
      )}
    </DialogContent>
  );
}

// ── Main page ────────────────────────────────────────────────────────────────

export default function Targets() {
  const [, nav] = useLocation();
  const [search, setSearch] = useState("");
  const [tagFilter, setTagFilter] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState("risk_score");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [showImport, setShowImport] = useState(false);
  const [tagTarget, setTagTarget] = useState<Target | null>(null);
  const [confirmDeleteTarget, setConfirmDeleteTarget] = useState<Target | null>(null);
  const { toast } = useToast();
  const qc = useQueryClient();

  const deleteTarget = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/targets/${id}`, { method: "DELETE", credentials: "include" }).then(async r => {
        if (!r.ok) throw new Error(await r.text());
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["/api/targets"] });
      toast({ title: "Target deleted", description: "Target removed from inventory." });
      setConfirmDeleteTarget(null);
    },
    onError: () => toast({ title: "Delete failed", description: "Could not delete this target. Please try again.", variant: "destructive" }),
  });

  const { data, isLoading } = useQuery<TargetsResponse>({
    queryKey: ["/api/targets", search, tagFilter, sortBy, sortDir],
    queryFn: () => {
      const params = new URLSearchParams({ sort_by: sortBy, sort_dir: sortDir, page_size: "100" });
      if (search) params.set("search", search);
      if (tagFilter) params.set("tag", tagFilter);
      return fetch(`/api/targets?${params}`, { credentials: "include" }).then((r) => r.json());
    },
    staleTime: 15000,
  });

  const targets = data?.items ?? [];
  const allTags = data?.all_tags ?? [];

  function toggleSort(field: string) {
    if (sortBy === field) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortBy(field); setSortDir("desc"); }
  }

  function launchScan(url: string) {
    nav(`/scans/new?url=${encodeURIComponent(url)}`);
  }

  const riskColor = (score: number) =>
    score > 80 ? "text-red-500" : score > 60 ? "text-orange-500" : score > 30 ? "text-yellow-500" : "text-green-500";

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Targets Inventory</h1>
          <p className="text-muted-foreground text-sm">Manage and monitor all scanned domains and infrastructure.</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => setShowImport(true)}>
            <Upload className="w-4 h-4 mr-1.5" />Bulk Import
          </Button>
          <Button size="sm" onClick={() => nav("/scans/new")}>
            <Play className="w-4 h-4 mr-1.5" />New Scan
          </Button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative">
          <Search className="absolute left-2.5 top-2 h-4 w-4 text-muted-foreground" />
          <Input placeholder="Search domains…" className="pl-8 h-8 w-56 text-sm" value={search}
            onChange={(e) => setSearch(e.target.value)} />
        </div>
        <div className="flex items-center gap-1.5">
          <Tag className="w-4 h-4 text-muted-foreground" />
          <button
            onClick={() => setTagFilter(null)}
            className={`text-xs px-2 py-1 rounded-full border transition-colors ${!tagFilter ? "border-primary bg-primary/10 text-primary" : "border-border text-muted-foreground hover:bg-accent"}`}>
            All
          </button>
          {allTags.map((tag) => (
            <button key={tag} onClick={() => setTagFilter(tagFilter === tag ? null : tag)}
              className={`text-xs px-2 py-1 rounded-full border transition-colors ${tagFilter === tag ? "border-primary bg-primary/10 text-primary" : "border-border text-muted-foreground hover:bg-accent"}`}>
              {tag}
            </button>
          ))}
        </div>
        <span className="ml-auto text-xs text-muted-foreground">{targets.length} target{targets.length !== 1 ? "s" : ""}</span>
      </div>

      {/* Table */}
      {isLoading ? (
        <TableSkeleton rows={6} cols={8} />
      ) : (
      <Card className="overflow-hidden">
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead className="bg-muted/40 border-b border-border">
                <tr>
                  <SortTh label="Domain" field="domain" current={sortBy} dir={sortDir} onClick={toggleSort} />
                  <th className="px-4 py-3 text-xs text-muted-foreground uppercase font-semibold">Tags / Tech</th>
                  <SortTh label="Risk" field="risk_score" current={sortBy} dir={sortDir} onClick={toggleSort} />
                  <th className="px-4 py-3 text-xs text-muted-foreground uppercase font-semibold">Trend</th>
                  <SortTh label="Findings" field="total_findings" current={sortBy} dir={sortDir} onClick={toggleSort} />
                  <SortTh label="Scans" field="total_scans" current={sortBy} dir={sortDir} onClick={toggleSort} />
                  <SortTh label="Last Scanned" field="last_scanned" current={sortBy} dir={sortDir} onClick={toggleSort} />
                  <th className="px-4 py-3 text-xs text-muted-foreground uppercase font-semibold">Health</th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {targets.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="px-4 py-16 text-center">
                      {search || tagFilter ? (
                        <div className="flex flex-col items-center gap-3">
                          <div className="w-12 h-12 rounded-full flex items-center justify-center bg-muted">
                            <Search className="w-6 h-6 text-muted-foreground" />
                          </div>
                          <p className="text-sm font-medium">No targets match your filters</p>
                          <p className="text-xs text-muted-foreground">Try clearing the search or tag filter</p>
                        </div>
                      ) : (
                        <div className="flex flex-col items-center gap-4">
                          <div className="w-16 h-16 rounded-2xl flex items-center justify-center"
                            style={{ background: "linear-gradient(135deg, rgba(124,58,237,0.2), rgba(168,85,247,0.1))", border: "1px solid rgba(124,58,237,0.3)" }}>
                            <TargetIcon className="w-8 h-8" style={{ color: "#a855f7" }} />
                          </div>
                          <div className="space-y-1">
                            <p className="text-sm font-semibold">No targets yet</p>
                            <p className="text-xs text-muted-foreground max-w-[260px]">
                              Add domains to monitor by running a scan or using Bulk Import.
                            </p>
                          </div>
                          <div className="flex items-center gap-2">
                            <Button size="sm" onClick={() => setShowImport(true)} variant="outline">
                              <Upload className="w-4 h-4 mr-1.5" />Bulk Import
                            </Button>
                            <Button size="sm" onClick={() => nav("/scans/new")}
                              style={{ background: "linear-gradient(135deg, #7c3aed, #a855f7)", color: "white", border: "none" }}>
                              <Play className="w-4 h-4 mr-1.5" />Run First Scan
                            </Button>
                          </div>
                        </div>
                      )}
                    </td>
                  </tr>
                ) : targets.map((target) => (
                  <tr key={target.id} className="hover:bg-muted/20 transition-colors group">
                    {/* Domain */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <Globe className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                        <div>
                          <Link href={`/targets/${target.id}`} className="font-mono font-medium hover:underline text-primary text-sm">
                            {target.domain}
                          </Link>
                          {target.subdomains.length > 0 && (
                            <div className="text-[10px] text-muted-foreground mt-0.5">
                              +{target.subdomains.length} subdomain{target.subdomains.length !== 1 ? "s" : ""}
                            </div>
                          )}
                        </div>
                      </div>
                    </td>

                    {/* Tags + tech */}
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1 max-w-[200px]">
                        {target.tags.slice(0, 3).map((t) => <TagPill key={t} tag={t} />)}
                        {target.tags.length > 3 && <span className="text-[10px] text-muted-foreground">+{target.tags.length - 3}</span>}
                        {target.tech_stack.slice(0, 2).map((t) => <TechBadge key={t} tech={t} />)}
                        {target.tech_stack.length > 2 && <span className="text-[10px] text-muted-foreground">+{target.tech_stack.length - 2}</span>}
                      </div>
                    </td>

                    {/* Risk score */}
                    <td className="px-4 py-3">
                      <span className={`font-bold text-base ${riskColor(target.risk_score)}`}>{target.risk_score}</span>
                      <span className="text-muted-foreground text-xs">/100</span>
                    </td>

                    {/* Sparkline */}
                    <td className="px-4 py-3">
                      <RiskSparkline history={target.risk_history} />
                    </td>

                    {/* Findings */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <span className="font-medium">{target.total_findings}</span>
                        {(target.critical_findings > 0 || target.high_findings > 0) && (
                          <span className="text-xs text-muted-foreground">
                            (<span className="text-red-500">{target.critical_findings}</span>
                            /<span className="text-orange-500">{target.high_findings}</span>)
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Scans */}
                    <td className="px-4 py-3 font-mono text-xs text-center">{target.total_scans}</td>

                    {/* Last scanned */}
                    <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap">
                      {target.last_scanned ? format(new Date(target.last_scanned), "MMM d, yyyy") : "Never"}
                    </td>

                    {/* Health */}
                    <td className="px-4 py-3"><HealthBadge lastScanned={target.last_scanned} /></td>

                    {/* Actions */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                        <Button size="sm" variant="ghost" className="h-7 px-2 text-xs"
                          onClick={() => launchScan(target.url || `https://${target.domain}`)}>
                          <Play className="w-3 h-3 mr-1" />Scan
                        </Button>
                        <Button size="sm" variant="ghost" className="h-7 px-2 text-xs"
                          onClick={() => setTagTarget(target)}>
                          <Tag className="w-3 h-3 mr-1" />Tags
                        </Button>
                        <Button size="sm" variant="ghost"
                          className="h-7 px-2 text-xs text-destructive hover:text-destructive hover:bg-destructive/10"
                          onClick={() => setConfirmDeleteTarget(target)}>
                          <Trash2 className="w-3 h-3" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
      )}

      {/* Dialogs */}
      <Dialog open={showImport} onOpenChange={setShowImport}>
        <BulkImportDialog onClose={() => setShowImport(false)} />
      </Dialog>

      <Dialog open={!!tagTarget} onOpenChange={(o) => { if (!o) setTagTarget(null); }}>
        {tagTarget && <TagEditorDialog target={tagTarget} onClose={() => setTagTarget(null)} />}
      </Dialog>

      <ConfirmDialog
        open={!!confirmDeleteTarget}
        onOpenChange={(o) => { if (!o) setConfirmDeleteTarget(null); }}
        title="Delete Target"
        description={`Remove "${confirmDeleteTarget?.domain}" from your inventory? Its scan history and findings will remain, but the target will no longer be monitored.`}
        confirmLabel="Delete Target"
        variant="destructive"
        loading={deleteTarget.isPending}
        onConfirm={() => { if (confirmDeleteTarget) deleteTarget.mutate(confirmDeleteTarget.id); }}
      />
    </div>
  );
}
