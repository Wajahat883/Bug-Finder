import { useState, useEffect, useCallback } from "react";
import { useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import {
  Search, Shield, Activity, Target, Wrench, X, ArrowRight,
} from "lucide-react";

interface SearchResult {
  id: string;
  type: "finding" | "scan" | "target" | "remediation";
  title: string;
  subtitle: string;
  href: string;
  severity?: string;
}

const SEV_COLOR: Record<string,string> = { critical:"#ef4444", high:"#f97316", medium:"#eab308", low:"#22d3ee" };
const TYPE_ICON: Record<string, React.ReactNode> = {
  finding: <Shield className="w-4 h-4" />,
  scan: <Activity className="w-4 h-4" />,
  target: <Target className="w-4 h-4" />,
  remediation: <Wrench className="w-4 h-4" />,
};

export function CommandSearch({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(0);
  const [, setLocation] = useLocation();

  const { data: findings = [] } = useQuery<any[]>({
    queryKey: ["/api/findings", "search", query],
    queryFn: () => fetch(`/api/findings?search=${encodeURIComponent(query)}&page_size=5`, { credentials: "include" }).then(r => r.json()).then(d => d?.items ?? []),
    enabled: query.length >= 2,
  });

  const { data: scans = [] } = useQuery<any[]>({
    queryKey: ["/api/scan-jobs", "search", query],
    queryFn: () => fetch(`/api/scan-jobs?limit=5`, { credentials: "include" }).then(r => r.json()).then(d => Array.isArray(d) ? d : d?.items ?? []),
    enabled: query.length >= 2,
  });

  const results: SearchResult[] = [
    ...findings.filter((f: any) => !query || f.title?.toLowerCase().includes(query.toLowerCase()) || f.endpoint?.toLowerCase().includes(query.toLowerCase())).slice(0, 5).map((f: any) => ({
      id: f.id, type: "finding" as const, title: f.title, subtitle: f.endpoint ?? "", href: `/findings/${f.id}`, severity: f.severity,
    })),
    ...scans.filter((s: any) => !query || s.target_url?.toLowerCase().includes(query.toLowerCase())).slice(0, 3).map((s: any) => ({
      id: s.id, type: "scan" as const, title: s.target_url, subtitle: `${s.status} · ${s.findings_count ?? 0} findings`, href: `/scans/${s.id}`,
    })),
  ];

  const QUICK_LINKS = [
    { title: "New Scan", href: "/scans/new", icon: <Activity className="w-4 h-4" /> },
    { title: "All Findings", href: "/findings", icon: <Shield className="w-4 h-4" /> },
    { title: "Dashboard", href: "/dashboard", icon: <Target className="w-4 h-4" /> },
    { title: "Remediations", href: "/remediations", icon: <Wrench className="w-4 h-4" /> },
  ];

  const navigate = useCallback((href: string) => {
    setLocation(href); onClose(); setQuery("");
  }, [setLocation, onClose]);

  useEffect(() => { setSelected(0); }, [results.length]);

  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      if (e.key === "ArrowDown") setSelected(s => Math.min(s + 1, (query ? results.length : QUICK_LINKS.length) - 1));
      if (e.key === "ArrowUp") setSelected(s => Math.max(s - 1, 0));
      if (e.key === "Enter") {
        if (query && results[selected]) navigate(results[selected].href);
        else if (!query && QUICK_LINKS[selected]) navigate(QUICK_LINKS[selected].href);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, results, selected, query, navigate, QUICK_LINKS]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh] bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div className="w-full max-w-2xl rounded-xl border border-border bg-card shadow-2xl overflow-hidden" onClick={e => e.stopPropagation()}>
        {/* Search input */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-border">
          <Search className="w-5 h-5 text-muted-foreground flex-shrink-0" />
          <input
            autoFocus
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Search findings, scans, targets..."
            className="flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
          />
          {query && (
            <button onClick={() => setQuery("")} className="text-muted-foreground hover:text-foreground">
              <X className="w-4 h-4" />
            </button>
          )}
          <kbd className="text-[10px] px-1.5 py-0.5 rounded border border-border text-muted-foreground">ESC</kbd>
        </div>

        {/* Results */}
        <div className="max-h-80 overflow-y-auto py-2">
          {query.length < 2 ? (
            <>
              <div className="px-4 py-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Quick Navigation</div>
              {QUICK_LINKS.map((link, i) => (
                <button key={link.href} className={`w-full flex items-center gap-3 px-4 py-2.5 text-sm hover:bg-accent/50 transition-colors ${selected === i ? "bg-accent/50" : ""}`}
                  onClick={() => navigate(link.href)}>
                  <span className="text-primary">{link.icon}</span>
                  <span>{link.title}</span>
                  <ArrowRight className="w-3.5 h-3.5 text-muted-foreground ml-auto" />
                </button>
              ))}
            </>
          ) : results.length === 0 ? (
            <div className="py-8 text-center text-sm text-muted-foreground">No results for "{query}"</div>
          ) : (
            <>
              <div className="px-4 py-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Results</div>
              {results.map((r, i) => (
                <button key={r.id} className={`w-full flex items-center gap-3 px-4 py-2.5 text-sm hover:bg-accent/50 transition-colors ${selected === i ? "bg-accent/50" : ""}`}
                  onClick={() => navigate(r.href)}>
                  <span className="text-muted-foreground">{TYPE_ICON[r.type]}</span>
                  <div className="flex-1 text-left min-w-0">
                    <div className="font-medium truncate">{r.title}</div>
                    <div className="text-xs text-muted-foreground truncate">{r.subtitle}</div>
                  </div>
                  {r.severity && (
                    <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded flex-shrink-0"
                      style={{ background: `${SEV_COLOR[r.severity]}22`, color: SEV_COLOR[r.severity] }}>
                      {r.severity}
                    </span>
                  )}
                </button>
              ))}
            </>
          )}
        </div>

        <div className="border-t border-border px-4 py-2 flex items-center gap-4 text-[10px] text-muted-foreground">
          <span><kbd className="px-1 py-0.5 rounded border border-border">↑↓</kbd> navigate</span>
          <span><kbd className="px-1 py-0.5 rounded border border-border">↵</kbd> open</span>
          <span><kbd className="px-1 py-0.5 rounded border border-border">ESC</kbd> close</span>
        </div>
      </div>
    </div>
  );
}
