import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { useState, useRef } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { format } from "date-fns";
import {
  Wrench, ExternalLink, LayoutGrid, List, Plus,
  AlertTriangle, Clock, CheckCircle2, Eye,
} from "lucide-react";

const COLUMNS: { id: string; label: string; color: string; icon: React.ReactNode }[] = [
  { id: "pending",     label: "Pending",     color: "#eab308", icon: <Clock className="w-4 h-4" /> },
  { id: "in_progress", label: "In Progress", color: "#3b82f6", icon: <Wrench className="w-4 h-4" /> },
  { id: "review",      label: "In Review",   color: "#a855f7", icon: <Eye className="w-4 h-4" /> },
  { id: "resolved",    label: "Resolved",    color: "#22c55e", icon: <CheckCircle2 className="w-4 h-4" /> },
];

const SEV_COLOR: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22d3ee",
};

function RemCard({
  rem,
  onDragStart,
  onNavigate,
}: {
  rem: any;
  onDragStart: (e: React.DragEvent, id: string) => void;
  onNavigate: (path: string) => void;
}) {
  return (
    <div
      draggable
      onDragStart={(e) => onDragStart(e, rem.id)}
      className="group rounded-lg border border-border bg-card p-3 cursor-grab active:cursor-grabbing hover:border-primary/40 transition-all select-none"
      style={{ boxShadow: "0 1px 4px rgba(0,0,0,.15)" }}
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <p className="text-sm font-medium leading-snug line-clamp-2">{rem.title}</p>
        {rem.sla_breached && (
          <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 text-destructive mt-0.5" />
        )}
      </div>

      {rem.description && (
        <p className="text-[11px] text-muted-foreground mb-2 line-clamp-2">{rem.description}</p>
      )}

      <div className="flex items-center justify-between mt-2">
        <div className="flex gap-1.5">
          {rem.severity && (
            <span
              className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded"
              style={{ background: `${SEV_COLOR[rem.severity] ?? "#6b7280"}22`, color: SEV_COLOR[rem.severity] ?? "#6b7280" }}
            >
              {rem.severity}
            </span>
          )}
        </div>
        <div className="flex items-center gap-1.5 opacity-0 group-hover:opacity-100 transition-opacity">
          {rem.finding_id && (
            <button
              className="text-[10px] text-muted-foreground hover:text-foreground flex items-center gap-0.5"
              onClick={(e) => { e.stopPropagation(); onNavigate(`/findings/${rem.finding_id}`); }}
            >
              <ExternalLink className="w-3 h-3" /> Finding
            </button>
          )}
        </div>
      </div>

      <div className="mt-2 text-[10px] text-muted-foreground font-mono">
        {format(new Date(rem.created_at), "MMM d, yyyy")}
      </div>
    </div>
  );
}

function KanbanColumn({
  col,
  items,
  onDragStart,
  onDrop,
  onNavigate,
}: {
  col: typeof COLUMNS[0];
  items: any[];
  onDragStart: (e: React.DragEvent, id: string) => void;
  onDrop: (status: string) => void;
  onNavigate: (path: string) => void;
}) {
  const [over, setOver] = useState(false);

  return (
    <div
      className="flex flex-col min-w-[260px] flex-1 rounded-xl border border-border"
      style={{ background: "hsl(var(--card))" }}
      onDragOver={(e) => { e.preventDefault(); setOver(true); }}
      onDragLeave={() => setOver(false)}
      onDrop={() => { setOver(false); onDrop(col.id); }}
    >
      {/* Column header */}
      <div
        className="flex items-center gap-2 px-4 py-3 rounded-t-xl border-b border-border"
        style={{ background: `${col.color}12`, borderTop: `3px solid ${col.color}` }}
      >
        <span style={{ color: col.color }}>{col.icon}</span>
        <span className="font-semibold text-sm">{col.label}</span>
        <span
          className="ml-auto text-xs font-bold px-2 py-0.5 rounded-full"
          style={{ background: `${col.color}22`, color: col.color }}
        >
          {items.length}
        </span>
      </div>

      {/* Cards */}
      <div
        className="flex-1 p-3 space-y-2.5 overflow-y-auto"
        style={{
          minHeight: 120,
          background: over ? `${col.color}08` : undefined,
          transition: "background 0.15s",
        }}
      >
        {items.length === 0 && (
          <div className="text-xs text-muted-foreground text-center py-6 border border-dashed border-border rounded-lg">
            Drop here
          </div>
        )}
        {items.map((r) => (
          <RemCard key={r.id} rem={r} onDragStart={onDragStart} onNavigate={onNavigate} />
        ))}
      </div>
    </div>
  );
}

export default function Remediations() {
  const [, setLocation] = useLocation();
  const [view, setView] = useState<"kanban" | "list">("kanban");
  const dragId = useRef<string | null>(null);
  const qc = useQueryClient();

  const { data, isLoading } = useQuery<any[]>({
    queryKey: ["/api/remediations"],
    queryFn: () =>
      fetch("/api/remediations?limit=200", { credentials: "include" }).then((r) => r.json()),
    select: (d) => (Array.isArray(d) ? d : (d as any)?.items ?? []),
  });

  const updateStatus = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      fetch(`/api/remediations/${id}`, {
        method: "PATCH",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      }).then((r) => r.json()),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["/api/remediations"] }),
  });

  const remediations: any[] = data ?? [];

  function onDragStart(e: React.DragEvent, id: string) {
    dragId.current = id;
    e.dataTransfer.effectAllowed = "move";
  }

  function onDrop(status: string) {
    if (!dragId.current) return;
    const rem = remediations.find((r) => r.id === dragId.current);
    if (rem && rem.status !== status) {
      updateStatus.mutate({ id: dragId.current, status });
    }
    dragId.current = null;
  }

  const byStatus = (s: string) => remediations.filter((r) => r.status === s);

  const stats = {
    total: remediations.length,
    pending: byStatus("pending").length,
    in_progress: byStatus("in_progress").length,
    resolved: byStatus("resolved").length,
    breached: remediations.filter((r) => r.sla_breached).length,
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
            <Wrench className="w-7 h-7" />
            Remediations
          </h1>
          <p className="text-muted-foreground mt-1">
            Drag cards between columns to update status.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant={view === "kanban" ? "default" : "outline"}
            size="sm"
            onClick={() => setView("kanban")}
          >
            <LayoutGrid className="w-4 h-4 mr-1.5" /> Kanban
          </Button>
          <Button
            variant={view === "list" ? "default" : "outline"}
            size="sm"
            onClick={() => setView("list")}
          >
            <List className="w-4 h-4 mr-1.5" /> List
          </Button>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: "Total", value: stats.total, color: "#6d28d9" },
          { label: "Pending", value: stats.pending, color: "#eab308" },
          { label: "In Progress", value: stats.in_progress, color: "#3b82f6" },
          { label: "Resolved", value: stats.resolved, color: "#22c55e" },
        ].map((s) => (
          <Card key={s.label} className="p-4">
            <div className="text-2xl font-bold" style={{ color: s.color }}>{s.value}</div>
            <div className="text-xs text-muted-foreground mt-0.5">{s.label}</div>
          </Card>
        ))}
      </div>

      {stats.breached > 0 && (
        <div className="flex items-center gap-2 px-4 py-3 rounded-lg border border-destructive/30 bg-destructive/10 text-sm text-destructive">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          <span><strong>{stats.breached}</strong> remediation{stats.breached !== 1 ? "s" : ""} have breached SLA deadlines.</span>
        </div>
      )}

      {isLoading ? (
        <div className="p-12 text-center text-muted-foreground">Loading remediations…</div>
      ) : view === "kanban" ? (
        /* ── KANBAN ── */
        <div className="flex gap-4 overflow-x-auto pb-4" style={{ minHeight: 400 }}>
          {COLUMNS.map((col) => (
            <KanbanColumn
              key={col.id}
              col={col}
              items={byStatus(col.id)}
              onDragStart={onDragStart}
              onDrop={onDrop}
              onNavigate={setLocation}
            />
          ))}
        </div>
      ) : (
        /* ── LIST ── */
        <div className="space-y-3">
          {remediations.length === 0 ? (
            <div className="p-12 text-center text-muted-foreground border border-dashed border-border rounded-lg">
              No remediation tasks. Create one from a finding detail page.
            </div>
          ) : (
            remediations.map((r) => {
              const col = COLUMNS.find((c) => c.id === r.status) ?? COLUMNS[0];
              return (
                <Card key={r.id} className="overflow-hidden">
                  <div className="flex flex-col md:flex-row">
                    <div className="flex-1 p-5">
                      <div className="flex items-center gap-3 mb-2">
                        <span style={{ color: col.color }}>{col.icon}</span>
                        <h3 className="font-semibold">{r.title}</h3>
                        <Badge
                          variant="outline"
                          className="ml-auto capitalize text-xs"
                          style={{ borderColor: `${col.color}40`, color: col.color, background: `${col.color}12` }}
                        >
                          {col.label}
                        </Badge>
                        {r.sla_breached && (
                          <Badge variant="destructive" className="text-xs">SLA Breached</Badge>
                        )}
                      </div>
                      {r.description && (
                        <p className="text-sm text-muted-foreground mb-3">{r.description}</p>
                      )}
                      <div className="text-xs text-muted-foreground">
                        Created {format(new Date(r.created_at), "MMM d, yyyy")}
                      </div>
                    </div>
                    <div className="bg-muted/30 p-4 md:w-52 border-t md:border-t-0 md:border-l border-border flex flex-col gap-2 justify-center">
                      <select
                        className="text-xs rounded border border-border bg-background px-2 py-1.5 w-full"
                        value={r.status}
                        onChange={(e) => updateStatus.mutate({ id: r.id, status: e.target.value })}
                      >
                        {COLUMNS.map((c) => (
                          <option key={c.id} value={c.id}>{c.label}</option>
                        ))}
                      </select>
                      {r.finding_id && (
                        <Button
                          variant="outline"
                          size="sm"
                          className="w-full text-xs"
                          onClick={() => setLocation(`/findings/${r.finding_id}`)}
                        >
                          <ExternalLink className="w-3.5 h-3.5 mr-1.5" />View Finding
                        </Button>
                      )}
                    </div>
                  </div>
                </Card>
              );
            })
          )}
        </div>
      )}
    </div>
  );
}
