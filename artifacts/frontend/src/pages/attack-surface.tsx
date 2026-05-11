import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useLocation } from "wouter";
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend,
  Treemap,
} from "recharts";
import {
  Globe, ShieldAlert, Network, Tag, ExternalLink, Play, AlertTriangle,
  ChevronUp, ChevronDown, ChevronsUpDown,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

// ── Types ────────────────────────────────────────────────────────────────────

interface AttackSurfaceData {
  summary: {
    total_targets: number; total_findings: number; critical: number;
    high: number; unique_endpoints: number; unique_categories: number;
  };
  category_data: Array<{ name: string; critical: number; high: number; medium: number; low: number; total: number }>;
  endpoint_inventory: Array<{ url: string; method: string; severity: string; parameters: string[]; last_seen: string; finding_count: number }>;
  heatmap: Array<Record<string, string>>;
  heatmap_categories: string[];
  subdomains: Array<{ subdomain: string; parent: string; target_id: string }>;
  exposure_trend: Array<{ week: string; critical: number; high: number }>;
  open_ports: Array<{ endpoint: string; title: string; severity: string; target: string }>;
  all_tags: string[];
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const SEV_ORDER = ["critical", "high", "medium", "low", "info", "none"];
const SEV_COLORS: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#6b7280", none: "transparent",
};
const SEV_BG: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400", high: "bg-orange-500/15 text-orange-400",
  medium: "bg-yellow-500/15 text-yellow-400", low: "bg-green-500/15 text-green-400",
  info: "bg-gray-500/15 text-gray-400", none: "",
};

function SevBadge({ severity }: { severity: string }) {
  const cls = SEV_BG[severity] ?? SEV_BG.info;
  return <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${cls}`}>{severity}</span>;
}

function HeatCell({ value }: { value: string }) {
  const color = SEV_COLORS[value] ?? "transparent";
  const label = value === "none" ? "" : value.slice(0, 4).toUpperCase();
  return (
    <div className="w-16 h-8 rounded flex items-center justify-center text-[9px] font-bold text-white"
      style={{ background: value === "none" ? "hsl(var(--muted))" : color, opacity: value === "none" ? 0.3 : 0.85 }}>
      {label}
    </div>
  );
}

function SortTh({ label, field, current, dir, onClick }: {
  label: string; field: string; current: string; dir: "asc" | "desc"; onClick: (f: string) => void;
}) {
  const active = current === field;
  return (
    <th className="px-3 py-2.5 cursor-pointer select-none whitespace-nowrap" onClick={() => onClick(field)}>
      <span className="flex items-center gap-1 text-xs text-muted-foreground uppercase font-semibold">
        {label}
        {active ? (dir === "asc" ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />) : <ChevronsUpDown className="w-3 h-3 opacity-40" />}
      </span>
    </th>
  );
}

// ── Custom Treemap content ────────────────────────────────────────────────────

function TreemapContent({ x, y, width, height, name, value, critical, high }: Record<string, unknown>) {
  const w = Number(width), h = Number(height);
  if (w < 30 || h < 20) return null;
  const hasCrit = Number(critical) > 0;
  const hasHigh = Number(high) > 0;
  const bg = hasCrit ? "#ef444430" : hasHigh ? "#f9731630" : "#6b728020";
  const border = hasCrit ? "#ef4444" : hasHigh ? "#f97316" : "#6b7280";
  return (
    <g>
      <rect x={Number(x)} y={Number(y)} width={w} height={h} fill={bg} stroke={border} strokeWidth={1} rx={4} />
      {w > 50 && h > 30 && (
        <>
          <text x={Number(x) + 8} y={Number(y) + 16} fill="currentColor" fontSize={11} fontWeight="600" className="fill-foreground">{String(name)}</text>
          {h > 44 && <text x={Number(x) + 8} y={Number(y) + 30} fill="currentColor" fontSize={10} opacity={0.6} className="fill-muted-foreground">{Number(value)} findings</text>}
        </>
      )}
    </g>
  );
}

// ── Main page ────────────────────────────────────────────────────────────────

export default function AttackSurface() {
  const [, nav] = useLocation();
  const [tagFilter, setTagFilter] = useState<string | null>(null);
  const [epSort, setEpSort] = useState("severity");
  const [epDir, setEpDir] = useState<"asc" | "desc">("asc");
  const [epSearch, setEpSearch] = useState("");
  const [activeTab, setActiveTab] = useState<"overview" | "endpoints" | "heatmap" | "subdomains" | "ports">("overview");

  const { data, isLoading } = useQuery<AttackSurfaceData>({
    queryKey: ["/api/attack-surface", tagFilter],
    queryFn: () => {
      const params = new URLSearchParams();
      if (tagFilter) params.set("tag", tagFilter);
      return fetch(`/api/attack-surface?${params}`, { credentials: "include" }).then((r) => r.json());
    },
    staleTime: 30000,
  });

  if (isLoading || !data) {
    return <div className="p-8 text-center text-muted-foreground">Loading attack surface data…</div>;
  }

  const { summary, category_data, endpoint_inventory, heatmap, heatmap_categories,
    subdomains, exposure_trend, open_ports, all_tags } = data;

  // Radar data — normalize to max 10 scale
  const radarMax = Math.max(...category_data.map((c) => c.total), 1);
  const radarData = category_data.slice(0, 8).map((c) => ({
    subject: c.name.length > 18 ? c.name.slice(0, 16) + "…" : c.name,
    value: Math.round((c.total / radarMax) * 10),
    fullMark: 10,
  }));

  // Treemap data
  const treemapData = category_data.map((c) => ({ name: c.name, size: c.total, value: c.total, critical: c.critical, high: c.high }));

  // Endpoint sort + filter
  const sortedEndpoints = [...endpoint_inventory]
    .filter((e) => !epSearch || e.url.toLowerCase().includes(epSearch.toLowerCase()))
    .sort((a, b) => {
      if (epSort === "severity") {
        const diff = SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity);
        return epDir === "asc" ? diff : -diff;
      }
      if (epSort === "findings") return epDir === "asc" ? a.finding_count - b.finding_count : b.finding_count - a.finding_count;
      if (epSort === "last_seen") return epDir === "asc"
        ? new Date(a.last_seen).getTime() - new Date(b.last_seen).getTime()
        : new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime();
      return 0;
    });

  function toggleEpSort(field: string) {
    if (epSort === field) setEpDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setEpSort(field); setEpDir("asc"); }
  }

  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "endpoints", label: `Endpoints (${endpoint_inventory.length})` },
    { id: "heatmap", label: "Risk Heatmap" },
    { id: "subdomains", label: `Subdomains (${subdomains.length})` },
    { id: "ports", label: `Open Ports (${open_ports.length})` },
  ] as const;

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Attack Surface</h1>
          <p className="text-muted-foreground text-sm">Full exposure map across all monitored targets.</p>
        </div>
        <Button size="sm" onClick={() => nav("/scans/new")}><Play className="w-4 h-4 mr-1.5" />New Scan</Button>
      </div>

      {/* Tag filter */}
      {all_tags.length > 0 && (
        <div className="flex items-center gap-2 flex-wrap">
          <Tag className="w-4 h-4 text-muted-foreground" />
          <button onClick={() => setTagFilter(null)}
            className={`text-xs px-2 py-1 rounded-full border transition-colors ${!tagFilter ? "border-primary bg-primary/10 text-primary" : "border-border text-muted-foreground hover:bg-accent"}`}>
            All Targets
          </button>
          {all_tags.map((tag) => (
            <button key={tag} onClick={() => setTagFilter(tagFilter === tag ? null : tag)}
              className={`text-xs px-2 py-1 rounded-full border transition-colors ${tagFilter === tag ? "border-primary bg-primary/10 text-primary" : "border-border text-muted-foreground hover:bg-accent"}`}>
              {tag}
            </button>
          ))}
        </div>
      )}

      {/* KPI row */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        {[
          { label: "Targets", value: summary.total_targets, color: "" },
          { label: "Total Findings", value: summary.total_findings, color: "" },
          { label: "Critical", value: summary.critical, color: "text-red-500" },
          { label: "High", value: summary.high, color: "text-orange-500" },
          { label: "Endpoints", value: summary.unique_endpoints, color: "" },
          { label: "Categories", value: summary.unique_categories, color: "" },
        ].map((k) => (
          <div key={k.label} className="border rounded-lg p-3 text-center">
            <div className={`text-2xl font-bold ${k.color}`}>{k.value}</div>
            <div className="text-xs text-muted-foreground mt-0.5">{k.label}</div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b">
        {tabs.map((t) => (
          <button key={t.id} onClick={() => setActiveTab(t.id)}
            className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
              activeTab === t.id ? "border-primary text-primary" : "border-transparent text-muted-foreground hover:text-foreground"
            }`}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ── Overview ── */}
      {activeTab === "overview" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {/* Radar */}
          {radarData.length > 2 && (
            <div className="border rounded-lg p-4">
              <h3 className="font-semibold text-sm mb-3">Exposure by Category (Radar)</h3>
              <ResponsiveContainer width="100%" height={260}>
                <RadarChart data={radarData} margin={{ top: 10, right: 30, bottom: 10, left: 30 }}>
                  <PolarGrid stroke="hsl(var(--border))" />
                  <PolarAngleAxis dataKey="subject" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
                  <PolarRadiusAxis domain={[0, 10]} tick={false} axisLine={false} />
                  <Radar name="Exposure" dataKey="value" stroke="#7c3aed" fill="#7c3aed" fillOpacity={0.25} strokeWidth={2} />
                </RadarChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Treemap */}
          {treemapData.length > 0 && (
            <div className="border rounded-lg p-4">
              <h3 className="font-semibold text-sm mb-3">Findings Distribution (Treemap)</h3>
              <ResponsiveContainer width="100%" height={260}>
                <Treemap data={treemapData} dataKey="size" aspectRatio={4 / 3} content={<TreemapContent />} />
              </ResponsiveContainer>
            </div>
          )}

          {/* Exposure trend */}
          <div className="border rounded-lg p-4 lg:col-span-2">
            <h3 className="font-semibold text-sm mb-3">Exposure Trend — Critical + High Findings (8 Weeks)</h3>
            <ResponsiveContainer width="100%" height={160}>
              <AreaChart data={exposure_trend} margin={{ top: 5, right: 10, bottom: 0, left: -20 }}>
                <defs>
                  <linearGradient id="critGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="highGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f97316" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" opacity={0.1} />
                <XAxis dataKey="week" tick={{ fontSize: 10 }} />
                <YAxis tick={{ fontSize: 10 }} />
                <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8 }} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Area type="monotone" dataKey="critical" stroke="#ef4444" fill="url(#critGrad)" strokeWidth={2} />
                <Area type="monotone" dataKey="high" stroke="#f97316" fill="url(#highGrad)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Category breakdown table */}
          <div className="border rounded-lg p-4 lg:col-span-2">
            <h3 className="font-semibold text-sm mb-3">Category Breakdown</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b">
                    <th className="text-left py-2 text-xs text-muted-foreground uppercase">Category</th>
                    <th className="py-2 text-xs text-muted-foreground uppercase text-center">Critical</th>
                    <th className="py-2 text-xs text-muted-foreground uppercase text-center">High</th>
                    <th className="py-2 text-xs text-muted-foreground uppercase text-center">Medium</th>
                    <th className="py-2 text-xs text-muted-foreground uppercase text-center">Low</th>
                    <th className="py-2 text-xs text-muted-foreground uppercase text-center">Total</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {category_data.map((c) => (
                    <tr key={c.name} className="hover:bg-muted/20">
                      <td className="py-2 font-medium">{c.name}</td>
                      <td className="py-2 text-center text-red-500 font-mono">{c.critical || "—"}</td>
                      <td className="py-2 text-center text-orange-500 font-mono">{c.high || "—"}</td>
                      <td className="py-2 text-center text-yellow-500 font-mono">{c.medium || "—"}</td>
                      <td className="py-2 text-center text-green-500 font-mono">{c.low || "—"}</td>
                      <td className="py-2 text-center font-bold">{c.total}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── Endpoint Inventory ── */}
      {activeTab === "endpoints" && (
        <div className="border rounded-lg overflow-hidden">
          <div className="p-3 border-b flex items-center gap-3">
            <div className="relative flex-1 max-w-sm">
              <input
                className="w-full text-sm border rounded-md px-3 py-1.5 bg-background pl-8"
                placeholder="Filter endpoints…"
                value={epSearch}
                onChange={(e) => setEpSearch(e.target.value)}
              />
              <Globe className="absolute left-2.5 top-2 w-4 h-4 text-muted-foreground" />
            </div>
            <span className="text-xs text-muted-foreground">{sortedEndpoints.length} endpoints</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-muted/40 border-b">
                <tr>
                  <th className="px-3 py-2.5 text-left text-xs text-muted-foreground uppercase font-semibold">URL</th>
                  <th className="px-3 py-2.5 text-left text-xs text-muted-foreground uppercase font-semibold">Method</th>
                  <SortTh label="Severity" field="severity" current={epSort} dir={epDir} onClick={toggleEpSort} />
                  <th className="px-3 py-2.5 text-left text-xs text-muted-foreground uppercase font-semibold">Parameters</th>
                  <SortTh label="Findings" field="findings" current={epSort} dir={epDir} onClick={toggleEpSort} />
                  <SortTh label="Last Seen" field="last_seen" current={epSort} dir={epDir} onClick={toggleEpSort} />
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {sortedEndpoints.length === 0 ? (
                  <tr><td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">No endpoints discovered yet. Run a scan to populate this inventory.</td></tr>
                ) : sortedEndpoints.map((ep, i) => (
                  <tr key={i} className="hover:bg-muted/20">
                    <td className="px-3 py-2 font-mono text-xs max-w-[300px] truncate" title={ep.url}>{ep.url}</td>
                    <td className="px-3 py-2">
                      <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-muted">{ep.method}</span>
                    </td>
                    <td className="px-3 py-2"><SevBadge severity={ep.severity} /></td>
                    <td className="px-3 py-2">
                      {ep.parameters.length > 0
                        ? <span className="text-xs font-mono text-muted-foreground">{ep.parameters.slice(0, 4).join(", ")}{ep.parameters.length > 4 ? `… +${ep.parameters.length - 4}` : ""}</span>
                        : <span className="text-muted-foreground text-xs">—</span>}
                    </td>
                    <td className="px-3 py-2 text-center font-mono text-xs">{ep.finding_count}</td>
                    <td className="px-3 py-2 text-xs text-muted-foreground whitespace-nowrap">
                      {ep.last_seen ? new Date(ep.last_seen).toLocaleDateString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Risk Heatmap ── */}
      {activeTab === "heatmap" && (
        <div className="border rounded-lg p-4 overflow-x-auto">
          <h3 className="font-semibold text-sm mb-4">Risk Heatmap — Target × Category</h3>
          {heatmap.length === 0 ? (
            <p className="text-muted-foreground text-sm">No heatmap data yet. Run scans to populate.</p>
          ) : (
            <table className="text-sm border-collapse">
              <thead>
                <tr>
                  <th className="text-left pr-4 py-2 text-xs text-muted-foreground font-medium min-w-[140px]">Target</th>
                  {heatmap_categories.map((cat) => (
                    <th key={cat} className="px-1 py-2 text-[10px] text-muted-foreground font-medium text-center min-w-[68px]">
                      {cat.length > 14 ? cat.slice(0, 12) + "…" : cat}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-border/30">
                {heatmap.map((row, i) => (
                  <tr key={i}>
                    <td className="pr-4 py-1.5 font-mono text-xs font-medium">{String(row.domain)}</td>
                    {heatmap_categories.map((cat) => (
                      <td key={cat} className="px-1 py-1.5 text-center">
                        <HeatCell value={String(row[cat] ?? "none")} />
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {/* Legend */}
          <div className="flex items-center gap-3 mt-4 text-xs text-muted-foreground">
            <span>Legend:</span>
            {["critical", "high", "medium", "low", "none"].map((s) => (
              <div key={s} className="flex items-center gap-1">
                <div className="w-4 h-4 rounded" style={{ background: SEV_COLORS[s] ?? "hsl(var(--muted))", opacity: s === "none" ? 0.3 : 0.85 }} />
                <span className="capitalize">{s}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Subdomains ── */}
      {activeTab === "subdomains" && (
        <div className="border rounded-lg overflow-hidden">
          <div className="p-3 border-b">
            <h3 className="font-semibold text-sm">Discovered Subdomains</h3>
            <p className="text-xs text-muted-foreground mt-0.5">Subdomains found during scanning — add them as targets to expand coverage.</p>
          </div>
          {subdomains.length === 0 ? (
            <div className="p-8 text-center text-muted-foreground text-sm">No subdomains discovered yet. Run a Deep scan with Subdomain Enum enabled.</div>
          ) : (
            <table className="w-full text-sm">
              <thead className="bg-muted/40 border-b">
                <tr>
                  <th className="px-4 py-2.5 text-left text-xs text-muted-foreground uppercase font-semibold">Subdomain</th>
                  <th className="px-4 py-2.5 text-left text-xs text-muted-foreground uppercase font-semibold">Parent Domain</th>
                  <th className="px-4 py-2.5"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {subdomains.map((s, i) => (
                  <tr key={i} className="hover:bg-muted/20 group">
                    <td className="px-4 py-2.5 font-mono text-sm font-medium">{s.subdomain}</td>
                    <td className="px-4 py-2.5 text-muted-foreground text-sm">
                      <Link href={`/targets/${s.target_id}`} className="hover:underline text-primary">{s.parent}</Link>
                    </td>
                    <td className="px-4 py-2.5 opacity-0 group-hover:opacity-100 transition-opacity">
                      <Button size="sm" variant="outline" className="h-6 text-xs px-2"
                        onClick={() => window.open(`/scans/new?url=${encodeURIComponent(`https://${s.subdomain}`)}`, "_self")}>
                        <Play className="w-3 h-3 mr-1" />Add & Scan
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ── Open Ports ── */}
      {activeTab === "ports" && (
        <div className="border rounded-lg overflow-hidden">
          <div className="p-3 border-b">
            <h3 className="font-semibold text-sm">Open Ports &amp; Exposed Services</h3>
            <p className="text-xs text-muted-foreground mt-0.5">Services discovered during port scanning across all targets.</p>
          </div>
          {open_ports.length === 0 ? (
            <div className="p-8 text-center text-muted-foreground text-sm">No port scan findings yet. Run a scan with the port scanner module.</div>
          ) : (
            <table className="w-full text-sm">
              <thead className="bg-muted/40 border-b">
                <tr>
                  <th className="px-4 py-2.5 text-left text-xs text-muted-foreground uppercase font-semibold">Service / Port</th>
                  <th className="px-4 py-2.5 text-left text-xs text-muted-foreground uppercase font-semibold">Finding</th>
                  <th className="px-4 py-2.5 text-left text-xs text-muted-foreground uppercase font-semibold">Target</th>
                  <th className="px-4 py-2.5 text-left text-xs text-muted-foreground uppercase font-semibold">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {open_ports.map((p, i) => (
                  <tr key={i} className="hover:bg-muted/20">
                    <td className="px-4 py-2.5 font-mono text-sm">{p.endpoint}</td>
                    <td className="px-4 py-2.5 text-sm">{p.title}</td>
                    <td className="px-4 py-2.5 text-sm text-muted-foreground font-mono">{
                      (() => { try { return new URL(p.target).hostname; } catch { return p.target; } })()
                    }</td>
                    <td className="px-4 py-2.5"><SevBadge severity={p.severity} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
