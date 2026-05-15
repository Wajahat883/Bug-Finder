import { useState, useEffect, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Bell, X, CheckCircle2, AlertTriangle, ShieldAlert, Activity } from "lucide-react";
import { format } from "date-fns";

interface Notification {
  id: string;
  type: string;
  title: string;
  message: string;
  read: boolean;
  created_at: string;
}

const TYPE_ICON: Record<string, React.ReactNode> = {
  critical: <ShieldAlert className="w-4 h-4 text-red-500" />,
  high: <AlertTriangle className="w-4 h-4 text-orange-500" />,
  scan: <Activity className="w-4 h-4 text-blue-400" />,
};

export function NotificationBell() {
  const [open, setOpen] = useState(false);
  const qc = useQueryClient();
  const ref = useRef<HTMLDivElement>(null);

  const { data: raw } = useQuery<unknown>({
    queryKey: ["/api/notifications"],
    queryFn: () => fetch("/api/notifications", { credentials: "include" }).then(r => r.json()),
    refetchInterval: 30000,
  });

  const notifications: Notification[] = Array.isArray(raw)
    ? (raw as Notification[])
    : ((raw as Record<string, unknown>)?.["notifications"] as Notification[] ?? []);

  const unreadCount = notifications.filter(n => !n.read).length;

  const markRead = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/notifications/${id}/read`, { method: "PATCH", credentials: "include" }).then(r => r.json()),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["/api/notifications"] }),
  });

  const markAllRead = useMutation({
    mutationFn: () =>
      fetch("/api/notifications/read-all", { method: "POST", credentials: "include" }).then(r => r.json()),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["/api/notifications"] }),
  });

  useEffect(() => {
    function handler(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(v => !v)}
        className="relative p-2 rounded-lg hover:bg-accent/50 transition-colors text-muted-foreground hover:text-foreground"
        aria-label="Notifications"
      >
        <Bell className="w-5 h-5" />
        {unreadCount > 0 && (
          <span className="absolute -top-0.5 -right-0.5 w-4 h-4 bg-red-500 text-white text-[9px] font-bold rounded-full flex items-center justify-center">
            {unreadCount > 9 ? "9+" : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-80 bg-card border border-border rounded-xl shadow-xl z-50 overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-border">
            <span className="font-semibold text-sm">
              Notifications{" "}
              {unreadCount > 0 && <span className="text-muted-foreground font-normal">({unreadCount} unread)</span>}
            </span>
            <div className="flex items-center gap-2">
              {unreadCount > 0 && (
                <button onClick={() => markAllRead.mutate()} className="text-xs text-primary hover:underline">
                  Mark all read
                </button>
              )}
              <button onClick={() => setOpen(false)} className="text-muted-foreground hover:text-foreground">
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          <div className="max-h-80 overflow-y-auto">
            {notifications.length === 0 ? (
              <div className="py-8 text-center text-muted-foreground text-sm flex flex-col items-center gap-2">
                <CheckCircle2 className="w-6 h-6 text-green-500" />
                All caught up!
              </div>
            ) : (
              notifications.slice(0, 20).map(n => (
                <div
                  key={n.id}
                  className={`flex items-start gap-3 px-4 py-3 border-b border-border/50 hover:bg-accent/20 cursor-pointer transition-colors ${!n.read ? "bg-primary/5" : ""}`}
                  onClick={() => { if (!n.read) markRead.mutate(n.id); }}
                >
                  <div className="mt-0.5 shrink-0">{TYPE_ICON[n.type] ?? <Bell className="w-4 h-4 text-muted-foreground" />}</div>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium truncate">{n.title}</div>
                    <div className="text-xs text-muted-foreground line-clamp-2">{n.message}</div>
                    <div className="text-[10px] text-muted-foreground/60 mt-0.5">
                      {format(new Date(n.created_at), "MMM d, HH:mm")}
                    </div>
                  </div>
                  {!n.read && <span className="w-2 h-2 bg-primary rounded-full mt-1.5 shrink-0" />}
                </div>
              ))
            )}
          </div>

          {notifications.length > 0 && (
            <div className="px-4 py-2 border-t border-border">
              <a href="/notifications" className="text-xs text-primary hover:underline">View all notifications</a>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
