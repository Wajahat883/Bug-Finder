import { useLocation } from "wouter";
import { useNotifications } from "@/hooks/use-notifications";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { format } from "date-fns";
import {
  Bell, BellOff, CheckCheck, ShieldAlert, Activity,
  AlertTriangle, XCircle, CheckSquare, Filter,
} from "lucide-react";
import { useState } from "react";

const TYPE_ICONS: Record<string, React.ReactNode> = {
  finding:       <ShieldAlert className="w-4 h-4" />,
  scan_complete: <Activity className="w-4 h-4" />,
  sla_breach:    <AlertTriangle className="w-4 h-4" />,
  fp_marked:     <XCircle className="w-4 h-4" />,
  remediation:   <CheckSquare className="w-4 h-4" />,
  system:        <Bell className="w-4 h-4" />,
};

const SEV_COLOR: Record<string, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#22d3ee",
};

export default function Notifications() {
  const [, setLocation] = useLocation();
  const { notifications, markRead, markAllRead, clearAll } = useNotifications();
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [readFilter, setReadFilter] = useState<"all" | "unread" | "read">("all");
  const [muted, setMuted] = useState(false);

  const filtered = notifications.filter(n => {
    if (typeFilter !== "all" && n.type !== typeFilter) return false;
    if (readFilter === "unread" && n.read) return false;
    if (readFilter === "read" && !n.read) return false;
    return true;
  });

  const unreadCount = notifications.filter(n => !n.read).length;

  const typeOptions = [
    { value: "all", label: "All" },
    { value: "finding", label: "Findings" },
    { value: "scan_complete", label: "Scans" },
    { value: "sla_breach", label: "SLA Breaches" },
    { value: "remediation", label: "Remediations" },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
            <Bell className="w-7 h-7" />
            Notification Center
          </h1>
          <p className="text-muted-foreground mt-1">
            Full history of all platform events — findings, scans, SLA breaches.
            {unreadCount > 0 && <span className="ml-2 text-primary font-medium">{unreadCount} unread</span>}
          </p>
        </div>
        <div className="flex gap-2 flex-wrap">
          <Button variant="outline" size="sm" onClick={() => setMuted(m => !m)}>
            {muted ? <Bell className="w-4 h-4 mr-1.5" /> : <BellOff className="w-4 h-4 mr-1.5" />}
            {muted ? "Unmute" : "Mute Sounds"}
          </Button>
          {unreadCount > 0 && (
            <Button variant="outline" size="sm" onClick={markAllRead}>
              <CheckCheck className="w-4 h-4 mr-1.5" />Mark All Read
            </Button>
          )}
          {notifications.length > 0 && (
            <Button variant="outline" size="sm" onClick={clearAll}
              className="text-destructive hover:text-destructive border-destructive/30">
              Clear All
            </Button>
          )}
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <Filter className="w-4 h-4 text-muted-foreground flex-shrink-0" />
        <div className="flex gap-1.5 flex-wrap">
          {typeOptions.map(t => (
            <button key={t.value} onClick={() => setTypeFilter(t.value)}
              className="text-[11px] font-medium px-2.5 py-1 rounded border transition-all"
              style={typeFilter === t.value
                ? { background: "hsl(var(--primary))", color: "white", borderColor: "hsl(var(--primary))" }
                : { borderColor: "hsl(var(--border))", color: "hsl(var(--muted-foreground))" }}>
              {t.label}
            </button>
          ))}
        </div>
        <div className="flex gap-1.5 ml-auto">
          {(["all", "unread", "read"] as const).map(r => (
            <button key={r} onClick={() => setReadFilter(r)}
              className="text-[11px] font-medium px-2.5 py-1 rounded border transition-all capitalize"
              style={readFilter === r
                ? { background: "hsl(var(--accent))", color: "hsl(var(--accent-foreground))", borderColor: "hsl(var(--border))" }
                : { borderColor: "hsl(var(--border))", color: "hsl(var(--muted-foreground))" }}>
              {r}
            </button>
          ))}
        </div>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm text-muted-foreground">{filtered.length} notification{filtered.length !== 1 ? "s" : ""}</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {filtered.length === 0 ? (
            <div className="py-16 text-center text-muted-foreground">
              <Bell className="w-8 h-8 mx-auto mb-3 opacity-30" />
              <p className="text-sm">No notifications{typeFilter !== "all" || readFilter !== "all" ? " matching filters" : " yet"}.</p>
            </div>
          ) : (
            <div className="divide-y" style={{ borderColor: "hsl(var(--border))" }}>
              {filtered.map(n => (
                <div key={n.id}
                  className="flex items-start gap-4 px-5 py-4 transition-colors hover:bg-accent/30 cursor-pointer"
                  style={{ background: n.read ? "transparent" : "hsl(var(--primary)/0.04)" }}
                  onClick={() => { markRead(n.id); if (n.href) setLocation(n.href); }}
                >
                  {/* Icon */}
                  <div className="flex-shrink-0 mt-0.5 p-2 rounded-md"
                    style={{ background: n.severity ? `${SEV_COLOR[n.severity] ?? "#6b7280"}20` : "hsl(var(--muted))", color: n.severity ? SEV_COLOR[n.severity] : "hsl(var(--muted-foreground))" }}>
                    {TYPE_ICONS[n.type] ?? <Bell className="w-4 h-4" />}
                  </div>

                  {/* Content */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-sm font-semibold">{n.title}</span>
                      {n.severity && (
                        <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded"
                          style={{ background: `${SEV_COLOR[n.severity]}25`, color: SEV_COLOR[n.severity] }}>
                          {n.severity}
                        </span>
                      )}
                      {!n.read && <span className="w-2 h-2 rounded-full bg-primary flex-shrink-0" />}
                    </div>
                    <p className="text-sm text-muted-foreground">{n.message}</p>

                    {/* Action buttons */}
                    {(n.href || n.findingId || n.scanId) && (
                      <div className="flex gap-2 mt-2" onClick={e => e.stopPropagation()}>
                        {n.href && (
                          <Button size="sm" variant="outline" className="h-6 text-[11px] px-2 py-0"
                            onClick={() => { markRead(n.id); setLocation(n.href!); }}>
                            View
                          </Button>
                        )}
                        {n.findingId && (
                          <Button size="sm" variant="outline" className="h-6 text-[11px] px-2 py-0"
                            onClick={async () => {
                              await fetch(`/api/findings/${n.findingId}`, {
                                method: "PATCH", credentials: "include",
                                headers: { "Content-Type": "application/json" },
                                body: JSON.stringify({ validation_status: "false_positive" }),
                              });
                              markRead(n.id);
                            }}>
                            Mark FP
                          </Button>
                        )}
                        {n.findingId && (
                          <Button size="sm" variant="outline" className="h-6 text-[11px] px-2 py-0"
                            onClick={async () => {
                              const finding = await fetch(`/api/findings/${n.findingId}`, { credentials: "include" }).then(r => r.json());
                              await fetch("/api/remediations", {
                                method: "POST", credentials: "include",
                                headers: { "Content-Type": "application/json" },
                                body: JSON.stringify({ finding_id: n.findingId, title: `Fix: ${finding.title}`, description: finding.recommended_fix ?? "" }),
                              });
                              markRead(n.id);
                            }}>
                            Create Remediation
                          </Button>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Time */}
                  <span className="text-[10px] text-muted-foreground font-mono flex-shrink-0 mt-0.5">
                    {format(n.time, "MMM d, HH:mm")}
                  </span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
