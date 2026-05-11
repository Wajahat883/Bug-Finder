import { useState, useRef, useCallback, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { format, subDays, startOfDay, eachDayOfInterval, isWithinInterval, parseISO } from "date-fns";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Download, ChevronDown, ChevronRight, X,
  Activity, ShieldAlert, CheckSquare, AlertTriangle, XCircle, Calendar,
} from "lucide-react";

// ─── Types ───────────────────────────────────────────────────────────────────

type ZoomLevel = "day" | "week" | "month" | "quarter";

type EventType = "scan_started" | "scan_completed" | "finding" | "remediation" | "sla_breach" | "fp_marked";

interface TimelineEvent {
  id: string;
  type: EventType;
  title: string;
  subtitle?: string;
  severity?: string;
  time: Date;
  scanId?: string;
  findingId?: string;
  meta?: Record<string, unknown>;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#22d3ee",
  info:     "#6b7280",
};

const LANES: { key: string; label: string; color: string }[] = [
  { key: "critical", label: "Critical",    color: "#ef4444" },
  { key: "high",     label: "High",        color: "#f97316" },
  { key: "medium",   label: "Medium",      color: "#eab308" },
  { key: "low",      label: "Low / Info",  color: "#22d3ee" },
  { key: "scan",     label: "Scans",       color: "#a855f7" },
  { key: "other",    label: "Other",       color: "#6b7280" },
];

const TYPE_ICON: Record<EventType, React.ReactNode> = {
  scan_started:   <Activity className="w-3.5 h-3.5" />,
  scan_completed: <Activity className="w-3.5 h-3.5" />,
  finding:        <ShieldAlert className="w-3.5 h-3.5" />,
  remediation:    <CheckSquare className="w-3.5 h-3.5" />,
  sla_breach:     <AlertTriangle className="w-3.5 h-3.5" />,
  fp_marked:      <XCircle className="w-3.5 h-3.5" />,
};

const ZOOM_DAYS: Record<ZoomLevel, number> = { day: 1, week: 7, month: 30, quarter: 90 };

// ─── Helpers ─────────────────────────────────────────────────────────────────

function laneForEvent(e: TimelineEvent): string {
  if (e.type === "scan_started" || e.type === "scan_completed") return "scan";
  if (e.type === "finding") return e.severity ?? "info";
  return "other";
}

function severityRank(s: string) {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[s] ?? 5;
}

// ─── Heatmap Strip ────────────────────────────────────────────────────────────

function HeatmapStrip({ events, days }: { events: TimelineEvent[]; days: number }) {
  const end = new Date();
  const start = subDays(end, days - 1);
  const allDays = eachDayOfInterval({ start, end });

  const countPerDay = new Map<string, number>();
  for (const e of events) {
    const key = format(startOfDay(e.time), "yyyy-MM-dd");
    countPerDay.set(key, (countPerDay.get(key) ?? 0) + 1);
  }

  const max = Math.max(1, ...countPerDay.values());

  return (
    <div className="mb-6">
      <p className="text-xs text-muted-foreground mb-1.5 font-medium">Finding density</p>
      <div className="flex gap-0.5 flex-wrap">
        {allDays.map((d) => {
          const key = format(d, "yyyy-MM-dd");
          const count = countPerDay.get(key) ?? 0;
          const intensity = count === 0 ? 0 : Math.ceil((count / max) * 4);
          const bg = count === 0
            ? "hsl(var(--muted))"
            : intensity === 1 ? "rgba(139,92,246,0.25)"
            : intensity === 2 ? "rgba(139,92,246,0.5)"
            : intensity === 3 ? "rgba(139,92,246,0.75)"
            : "#8b5cf6";
          return (
            <div
              key={key}
              title={`${format(d, "MMM d")} — ${count} event${count !== 1 ? "s" : ""}`}
              style={{ width: 12, height: 12, background: bg, borderRadius: 2, cursor: "default", flexShrink: 0 }}
            />
          );
        })}
      </div>
      <div className="flex items-center gap-1.5 mt-1">
        <span className="text-[10px] text-muted-foreground">Less</span>
        {[0.15, 0.35, 0.55, 0.75, 1].map((o, i) => (
          <div key={i} style={{ width: 10, height: 10, background: `rgba(139,92,246,${o})`, borderRadius: 2 }} />
        ))}
        <span className="text-[10px] text-muted-foreground">More</span>
      </div>
    </div>
  );
}

// ─── Swimlane View ────────────────────────────────────────────────────────────

function SwimlaneView({
  events,
  collapsed,
  onToggleCollapse,
  onSelect,
}: {
  events: TimelineEvent[];
  collapsed: Set<string>;
  onToggleCollapse: (id: string) => void;
  onSelect: (e: TimelineEvent) => void;
}) {
  // Group scan findings for connecting lines
  const scanFindings = new Map<string, TimelineEvent[]>();
  for (const e of events) {
    if (e.type === "finding" && e.scanId) {
      const arr = scanFindings.get(e.scanId) ?? [];
      arr.push(e);
      scanFindings.set(e.scanId, arr);
    }
  }

  return (
    <div className="space-y-3">
      {LANES.map((lane) => {
        const laneEvents = events
          .filter((e) => laneForEvent(e) === lane.key)
          .sort((a, b) => b.time.getTime() - a.time.getTime());

        if (laneEvents.length === 0) return null;

        const isCollapsed = collapsed.has(lane.key);

        return (
          <div key={lane.key} className="rounded-lg border overflow-hidden"
            style={{ borderColor: `${lane.color}30`, background: `${lane.color}08` }}>
            {/* Lane header */}
            <button
              className="w-full flex items-center justify-between px-4 py-2.5 hover:opacity-90 transition-opacity"
              style={{ background: `${lane.color}12` }}
              onClick={() => onToggleCollapse(lane.key)}
            >
              <div className="flex items-center gap-2">
                <div className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ background: lane.color }} />
                <span className="text-sm font-semibold" style={{ color: lane.color }}>{lane.label}</span>
                <span className="text-xs text-muted-foreground">({laneEvents.length})</span>
              </div>
              {isCollapsed ? <ChevronRight className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
            </button>

            {!isCollapsed && (
              <div className="divide-y" style={{ borderColor: `${lane.color}20` }}>
                {laneEvents.map((ev) => {
                  const scanFindingCount = ev.type === "scan_completed" && ev.scanId
                    ? (scanFindings.get(ev.scanId)?.length ?? 0)
                    : 0;

                  return (
                    <button
                      key={ev.id}
                      className="w-full flex items-start gap-3 px-4 py-2.5 text-left hover:bg-white/5 transition-colors"
                      onClick={() => onSelect(ev)}
                    >
                      <span className="mt-0.5 flex-shrink-0" style={{ color: lane.color }}>
                        {TYPE_ICON[ev.type]}
                      </span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-medium truncate">{ev.title}</span>
                          {ev.severity && (
                            <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded"
                              style={{ background: `${SEV_COLOR[ev.severity] ?? "#6b7280"}25`, color: SEV_COLOR[ev.severity] ?? "#6b7280" }}>
                              {ev.severity}
                            </span>
                          )}
                        </div>
                        {ev.subtitle && <p className="text-xs text-muted-foreground truncate">{ev.subtitle}</p>}
                        {scanFindingCount > 0 && (
                          <p className="text-[10px] mt-0.5" style={{ color: lane.color }}>
                            ↳ produced {scanFindingCount} finding{scanFindingCount !== 1 ? "s" : ""}
                          </p>
                        )}
                      </div>
                      <span className="text-[10px] text-muted-foreground font-mono flex-shrink-0">
                        {format(ev.time, "MMM d, HH:mm")}
                      </span>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─── Detail Side Panel ────────────────────────────────────────────────────────

function DetailPanel({ event, onClose }: { event: TimelineEvent; onClose: () => void }) {
  const [, setLocation] = useLocation();

  return (
    <div className="fixed right-0 top-0 h-full w-96 shadow-2xl z-40 flex flex-col"
      style={{ background: "hsl(var(--card))", borderLeft: "1px solid hsl(var(--border))" }}>
      <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: "hsl(var(--border))" }}>
        <h3 className="font-semibold text-sm">Event Detail</h3>
        <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-muted-foreground">{TYPE_ICON[event.type]}</span>
            <Badge variant="outline" className="text-[10px] uppercase">{event.type.replace(/_/g, " ")}</Badge>
          </div>
          <h2 className="text-lg font-bold mt-2">{event.title}</h2>
          {event.subtitle && <p className="text-sm text-muted-foreground mt-1">{event.subtitle}</p>}
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div className="rounded-md p-3" style={{ background: "hsl(var(--muted))" }}>
            <p className="text-[10px] text-muted-foreground uppercase mb-1">Time</p>
            <p className="text-sm font-mono">{format(event.time, "MMM d, yyyy")}</p>
            <p className="text-xs text-muted-foreground">{format(event.time, "HH:mm:ss")}</p>
          </div>
          {event.severity && (
            <div className="rounded-md p-3" style={{ background: `${SEV_COLOR[event.severity]}20` }}>
              <p className="text-[10px] text-muted-foreground uppercase mb-1">Severity</p>
              <p className="text-sm font-bold uppercase" style={{ color: SEV_COLOR[event.severity] }}>{event.severity}</p>
            </div>
          )}
        </div>

        {event.meta && Object.keys(event.meta).length > 0 && (
          <div>
            <p className="text-xs font-semibold text-muted-foreground uppercase mb-2">Details</p>
            <div className="space-y-1.5">
              {Object.entries(event.meta).map(([k, v]) => (
                <div key={k} className="flex items-start justify-between gap-3 text-sm">
                  <span className="text-muted-foreground capitalize">{k.replace(/_/g, " ")}</span>
                  <span className="font-mono text-xs text-right max-w-[180px] truncate" title={String(v)}>{String(v)}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="pt-2 space-y-2">
          {event.scanId && (
            <Button size="sm" variant="outline" className="w-full" onClick={() => { setLocation(`/scans/${event.scanId}`); onClose(); }}>
              View Scan
            </Button>
          )}
          {event.findingId && (
            <Button size="sm" variant="outline" className="w-full" onClick={() => { setLocation(`/findings/${event.findingId}`); onClose(); }}>
              View Finding
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function Timeline() {
  const [zoom, setZoom] = useState<ZoomLevel>("week");
  const [enabledTypes, setEnabledTypes] = useState<Set<EventType>>(
    new Set(["scan_started", "scan_completed", "finding", "remediation", "sla_breach", "fp_marked"])
  );
  const [collapsedLanes, setCollapsedLanes] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<TimelineEvent | null>(null);
  const [dateFrom, setDateFrom] = useState(() => format(subDays(new Date(), 7), "yyyy-MM-dd"));
  const [dateTo, setDateTo] = useState(() => format(new Date(), "yyyy-MM-dd"));
  const exportRef = useRef<HTMLDivElement>(null);

  // Sync date range with zoom
  useEffect(() => {
    const days = ZOOM_DAYS[zoom];
    setDateFrom(format(subDays(new Date(), days), "yyyy-MM-dd"));
    setDateTo(format(new Date(), "yyyy-MM-dd"));
  }, [zoom]);

  const { data: scansRaw = [] } = useQuery<Array<Record<string, unknown>>>({
    queryKey: ["/api/scan-jobs", "timeline"],
    queryFn: () =>
      fetch("/api/scan-jobs?page_size=200", { credentials: "include" })
        .then(r => r.json()).then(d => d.items ?? []),
  });

  const { data: findingsRaw = [] } = useQuery<Array<Record<string, unknown>>>({
    queryKey: ["/api/findings", "timeline"],
    queryFn: () =>
      fetch("/api/findings?page_size=200", { credentials: "include" })
        .then(r => r.json()).then(d => d.items ?? []),
  });

  const { data: remediationsRaw = [] } = useQuery<Array<Record<string, unknown>>>({
    queryKey: ["/api/remediations", "timeline"],
    queryFn: () =>
      fetch("/api/remediations?page_size=200", { credentials: "include" })
        .then(r => r.json()).then(d => d.items ?? []),
  });

  // Build unified event list
  const allEvents: TimelineEvent[] = [];

  for (const s of scansRaw) {
    if (s.created_at) {
      allEvents.push({
        id: `scan-start-${s.id}`,
        type: "scan_started",
        title: `Scan started — ${s.target_url}`,
        subtitle: `Profile: ${s.scan_profile}`,
        time: new Date(String(s.created_at)),
        scanId: String(s.id),
        meta: { target: s.target_url, profile: s.scan_profile, status: s.status },
      });
    }
    if (s.completed_at) {
      allEvents.push({
        id: `scan-done-${s.id}`,
        type: "scan_completed",
        title: `Scan completed — ${s.target_url}`,
        subtitle: `Risk: ${s.risk_score}/100 · ${s.findings_count} findings`,
        time: new Date(String(s.completed_at)),
        scanId: String(s.id),
        meta: { risk_score: s.risk_score, findings: s.findings_count, critical: s.critical_count, high: s.high_count },
      });
    }
  }

  for (const f of findingsRaw) {
    allEvents.push({
      id: `finding-${f.id}`,
      type: f.validation_status === "false_positive" ? "fp_marked" : "finding",
      title: String(f.title),
      subtitle: String(f.endpoint ?? f.target_url),
      severity: String(f.severity),
      time: new Date(String(f.created_at)),
      scanId: String(f.scan_job_id ?? ""),
      findingId: String(f.id),
      meta: { severity: f.severity, cvss: f.cvss_score, cwe: f.cwe_id, category: f.category },
    });
  }

  for (const r of remediationsRaw) {
    allEvents.push({
      id: `rem-${r.id}`,
      type: r.sla_breached ? "sla_breach" : "remediation",
      title: String(r.title),
      subtitle: r.sla_breached ? `SLA breached — ${r.sla_severity}` : `Status: ${r.status}`,
      severity: r.sla_severity ? String(r.sla_severity) : undefined,
      time: new Date(String(r.created_at)),
      meta: { status: r.status, sla_breached: r.sla_breached, severity: r.sla_severity },
    });
  }

  // Filter by date range and enabled types
  const from = startOfDay(parseISO(dateFrom));
  const to = startOfDay(parseISO(dateTo));

  const filtered = allEvents.filter((e) => {
    if (!enabledTypes.has(e.type)) return false;
    return isWithinInterval(startOfDay(e.time), { start: from, end: to });
  }).sort((a, b) => b.time.getTime() - a.time.getTime());

  function toggleType(t: EventType) {
    setEnabledTypes(prev => {
      const next = new Set(prev);
      if (next.has(t)) next.delete(t); else next.add(t);
      return next;
    });
  }

  function toggleLane(key: string) {
    setCollapsedLanes(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }

  function exportCSV() {
    const rows = [
      ["Time", "Type", "Title", "Subtitle", "Severity"],
      ...filtered.map(e => [
        format(e.time, "yyyy-MM-dd HH:mm:ss"),
        e.type,
        `"${e.title.replace(/"/g, '""')}"`,
        `"${(e.subtitle ?? "").replace(/"/g, '""')}"`,
        e.severity ?? "",
      ].join(",")),
    ].join("\n");
    const blob = new Blob([rows], { type: "text/csv" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = `timeline-${dateFrom}-${dateTo}.csv`; a.click();
  }

  const TYPE_LABELS: Record<EventType, string> = {
    scan_started: "Scan Started",
    scan_completed: "Scan Completed",
    finding: "Finding",
    remediation: "Remediation",
    sla_breach: "SLA Breach",
    fp_marked: "FP Marked",
  };

  const days = Math.max(1, Math.ceil((to.getTime() - from.getTime()) / 86400000) + 1);

  return (
    <div className="space-y-5" style={{ paddingRight: selected ? 400 : 0, transition: "padding-right 0.2s" }}>
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Activity Timeline</h1>
          <p className="text-muted-foreground">Swimlane view of all security events — scans, findings, remediations.</p>
        </div>
        <Button variant="outline" size="sm" onClick={exportCSV}>
          <Download className="w-4 h-4 mr-1.5" />Export CSV
        </Button>
      </div>

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-3">
        {/* Zoom pills */}
        <div className="flex items-center gap-1 p-1 rounded-md" style={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))" }}>
          {(["day", "week", "month", "quarter"] as ZoomLevel[]).map(z => (
            <button key={z} onClick={() => setZoom(z)}
              className="px-3 py-1 text-xs font-semibold rounded capitalize transition-all"
              style={zoom === z
                ? { background: "hsl(var(--primary))", color: "white" }
                : { color: "hsl(var(--muted-foreground))" }}>
              {z}
            </button>
          ))}
        </div>

        {/* Date range picker */}
        <div className="flex items-center gap-2">
          <Calendar className="w-3.5 h-3.5 text-muted-foreground" />
          <input type="date" value={dateFrom} onChange={e => setDateFrom(e.target.value)}
            className="text-xs bg-card border border-border rounded px-2 py-1 outline-none" />
          <span className="text-xs text-muted-foreground">to</span>
          <input type="date" value={dateTo} onChange={e => setDateTo(e.target.value)}
            className="text-xs bg-card border border-border rounded px-2 py-1 outline-none" />
        </div>

        {/* Event type filters */}
        <div className="flex items-center gap-1.5 flex-wrap">
          {(Object.keys(TYPE_LABELS) as EventType[]).map(t => (
            <button key={t} onClick={() => toggleType(t)}
              className="flex items-center gap-1.5 text-[10px] px-2 py-1 rounded border transition-all"
              style={enabledTypes.has(t)
                ? { background: "hsl(var(--primary)/0.15)", borderColor: "hsl(var(--primary)/0.4)", color: "hsl(var(--primary))" }
                : { background: "hsl(var(--card))", borderColor: "hsl(var(--border))", color: "hsl(var(--muted-foreground))" }}>
              {TYPE_ICON[t]}
              {TYPE_LABELS[t]}
            </button>
          ))}
        </div>
      </div>

      {/* Heatmap */}
      <Card>
        <CardContent className="pt-4 pb-3">
          <HeatmapStrip events={filtered} days={days} />
          <div className="flex items-center gap-4 text-xs text-muted-foreground mt-1">
            <span>{filtered.length} events in range</span>
            <span>·</span>
            <span>{days} day{days !== 1 ? "s" : ""} shown</span>
          </div>
        </CardContent>
      </Card>

      {/* Swimlanes */}
      <div ref={exportRef}>
        {filtered.length === 0 ? (
          <Card>
            <CardContent className="py-16 text-center text-muted-foreground">
              No events in this date range. Adjust filters or date range.
            </CardContent>
          </Card>
        ) : (
          <SwimlaneView
            events={filtered}
            collapsed={collapsedLanes}
            onToggleCollapse={toggleLane}
            onSelect={setSelected}
          />
        )}
      </div>

      {/* Side panel */}
      {selected && <DetailPanel event={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
