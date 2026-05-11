import { useState, useEffect, useCallback, useRef } from "react";
import { useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import {
  Search, ShieldAlert, Activity, Target, CheckSquare,
  LayoutDashboard, Settings, Sparkles, TrendingUp, X,
} from "lucide-react";

interface SearchResult {
  id: string;
  type: "finding" | "scan" | "target" | "page";
  title: string;
  subtitle?: string;
  severity?: string;
  href: string;
}

const PAGES: SearchResult[] = [
  { id: "p-dashboard",   type: "page", title: "Dashboard",        href: "/dashboard",      subtitle: "Overview & KPIs" },
  { id: "p-scans",       type: "page", title: "Scans",            href: "/scans",           subtitle: "All vulnerability scans" },
  { id: "p-findings",    type: "page", title: "Findings",         href: "/findings",        subtitle: "All discovered vulnerabilities" },
  { id: "p-targets",     type: "page", title: "Targets",          href: "/targets",         subtitle: "Monitored domains" },
  { id: "p-remediations",type: "page", title: "Remediations",     href: "/remediations",    subtitle: "Fix tracking" },
  { id: "p-executive",   type: "page", title: "Executive",        href: "/executive",       subtitle: "Leadership dashboard" },
  { id: "p-settings",    type: "page", title: "Settings",         href: "/settings",        subtitle: "Platform configuration" },
  { id: "p-integrations",type: "page", title: "Integrations",     href: "/integrations",    subtitle: "GitHub, Slack, webhooks" },
  { id: "p-ai-triage",   type: "page", title: "AI Triage",        href: "/ai-triage",       subtitle: "AI-powered analysis" },
  { id: "p-new-scan",    type: "page", title: "New Scan",         href: "/scans/new",       subtitle: "Start a vulnerability scan" },
  { id: "p-cvss",        type: "page", title: "CVSS Calculator",  href: "/cvss",            subtitle: "Calculate CVSS 3.1 scores" },
  { id: "p-compliance",  type: "page", title: "Compliance",       href: "/compliance",      subtitle: "Compliance dashboard" },
];

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400",
  high: "bg-orange-500/20 text-orange-400",
  medium: "bg-yellow-500/20 text-yellow-400",
  low: "bg-green-500/20 text-green-400",
  info: "bg-gray-500/20 text-gray-400",
};

const TYPE_ICONS: Record<string, React.ReactNode> = {
  finding: <ShieldAlert className="w-4 h-4" />,
  scan:    <Activity className="w-4 h-4" />,
  target:  <Target className="w-4 h-4" />,
  page:    <LayoutDashboard className="w-4 h-4" />,
};

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(0);
  const [, nav] = useLocation();
  const inputRef = useRef<HTMLInputElement>(null);

  const { data: findingsData } = useQuery({
    queryKey: ["/api/findings/search", query],
    queryFn: () =>
      fetch(`/api/findings?search=${encodeURIComponent(query)}&page_size=5`, { credentials: "include" })
        .then((r) => r.json())
        .then((d) => d.items ?? []),
    enabled: query.length > 1,
    staleTime: 5000,
  });

  const { data: scansData } = useQuery({
    queryKey: ["/api/scans/search", query],
    queryFn: () =>
      fetch(`/api/scan-jobs?search=${encodeURIComponent(query)}&page_size=5`, { credentials: "include" })
        .then((r) => r.json())
        .then((d) => d.items ?? []),
    enabled: query.length > 1,
    staleTime: 5000,
  });

  const { data: targetsData } = useQuery({
    queryKey: ["/api/targets/search", query],
    queryFn: () =>
      fetch(`/api/targets?search=${encodeURIComponent(query)}&page_size=5`, { credentials: "include" })
        .then((r) => r.json())
        .then((d) => d.items ?? []),
    enabled: query.length > 1,
    staleTime: 5000,
  });

  const filteredPages = PAGES.filter(
    (p) => !query || p.title.toLowerCase().includes(query.toLowerCase()) || (p.subtitle ?? "").toLowerCase().includes(query.toLowerCase())
  );

  const findings: SearchResult[] = ((findingsData ?? []) as Array<Record<string, unknown>>).map((f) => ({
    id: String(f["id"]),
    type: "finding" as const,
    title: String(f["title"]),
    subtitle: String(f["endpoint"] ?? ""),
    severity: String(f["severity"]),
    href: `/findings/${f["id"]}`,
  }));

  const scans: SearchResult[] = ((scansData ?? []) as Array<Record<string, unknown>>).map((s) => ({
    id: String(s["id"]),
    type: "scan" as const,
    title: String(s["target_url"]),
    subtitle: `${String(s["scan_profile"])} · ${String(s["status"])}`,
    href: `/scans/${s["id"]}`,
  }));

  const targets: SearchResult[] = ((targetsData ?? []) as Array<Record<string, unknown>>).map((t) => ({
    id: String(t["id"]),
    type: "target" as const,
    title: String(t["domain"]),
    subtitle: `Risk: ${t["risk_score"]}/100`,
    href: `/targets/${t["id"]}`,
  }));

  const groups: Array<{ label: string; results: SearchResult[] }> = [];
  if (findings.length > 0) groups.push({ label: "Findings", results: findings });
  if (scans.length > 0)    groups.push({ label: "Scans",    results: scans });
  if (targets.length > 0)  groups.push({ label: "Targets",  results: targets });
  if (filteredPages.length > 0) groups.push({ label: "Pages", results: filteredPages.slice(0, 5) });

  const allResults = groups.flatMap((g) => g.results);

  useEffect(() => { setSelected(0); }, [query]);
  useEffect(() => {
    if (open) {
      setQuery("");
      setSelected(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [open]);

  const navigate = useCallback((href: string) => {
    nav(href);
    onClose();
  }, [nav, onClose]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!open) return;
      if (e.key === "Escape") { onClose(); return; }
      if (e.key === "ArrowDown") { e.preventDefault(); setSelected((s) => Math.min(s + 1, allResults.length - 1)); }
      if (e.key === "ArrowUp")   { e.preventDefault(); setSelected((s) => Math.max(s - 1, 0)); }
      if (e.key === "Enter" && allResults[selected]) navigate(allResults[selected].href);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, allResults, selected, navigate, onClose]);

  if (!open) return null;

  let flatIdx = 0;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh]" onClick={onClose}>
      <div
        className="w-full max-w-xl rounded-xl overflow-hidden shadow-2xl"
        style={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))" }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search input */}
        <div className="flex items-center gap-3 px-4 py-3 border-b" style={{ borderColor: "hsl(var(--border))" }}>
          <Search className="w-4 h-4 flex-shrink-0 text-muted-foreground" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search findings, scans, targets, pages…"
            className="flex-1 bg-transparent outline-none text-sm placeholder:text-muted-foreground"
          />
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results */}
        <div className="max-h-96 overflow-y-auto py-1">
          {allResults.length === 0 && query.length > 0 ? (
            <div className="px-4 py-8 text-center text-sm text-muted-foreground">No results for "{query}"</div>
          ) : allResults.length === 0 ? (
            <div className="px-4 py-4 text-center text-sm text-muted-foreground">Type to search…</div>
          ) : (
            groups.map((group) => (
              <div key={group.label}>
                <div className="px-4 pt-3 pb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{group.label}</div>
                {group.results.map((result) => {
                  const idx = flatIdx++;
                  const isSelected = idx === selected;
                  return (
                    <button
                      key={result.id}
                      className="w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors"
                      style={{ background: isSelected ? "hsl(var(--accent))" : "transparent" }}
                      onMouseEnter={() => setSelected(idx)}
                      onClick={() => navigate(result.href)}
                    >
                      <span className="text-muted-foreground flex-shrink-0">{TYPE_ICONS[result.type]}</span>
                      <div className="flex-1 min-w-0">
                        <span className="text-sm font-medium truncate block">{result.title}</span>
                        {result.subtitle && <span className="text-xs text-muted-foreground truncate block">{result.subtitle}</span>}
                      </div>
                      {result.severity && (
                        <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded flex-shrink-0 ${SEV_COLORS[result.severity] ?? ""}`}>
                          {result.severity}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            ))
          )}
        </div>

        {/* Footer hints */}
        <div className="px-4 py-2 border-t flex items-center gap-3 text-[10px] text-muted-foreground" style={{ borderColor: "hsl(var(--border))" }}>
          <span><kbd className="px-1 rounded border border-border font-mono">↑↓</kbd> navigate</span>
          <span><kbd className="px-1 rounded border border-border font-mono">↵</kbd> open</span>
          <span><kbd className="px-1 rounded border border-border font-mono">Esc</kbd> close</span>
          <span className="ml-auto">Also: <kbd className="px-1 rounded border border-border font-mono">N</kbd> new scan &nbsp; <kbd className="px-1 rounded border border-border font-mono">F</kbd> findings</span>
        </div>
      </div>
    </div>
  );
}
