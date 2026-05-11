import { Link, useLocation } from "wouter";
import { useGetMe } from "@/api-client";
import { useTheme } from "next-themes";
import {
  Activity, LayoutDashboard, Search, Target, ShieldAlert,
  Bell, CheckSquare, Shield, Settings, Cpu, ScrollText,
  Calculator, Network, TrendingUp, Clock, Webhook, LogOut,
  ChevronDown, ChevronRight, Bookmark, GitCompare, ClipboardCheck,
  Timer, Sparkles, Moon, Sun, X, Contrast, ExternalLink,
  UserCircle, KeyRound,
} from "lucide-react";
import { useState, useEffect, useRef } from "react";
import { CommandPalette } from "./command-palette";
import { CommandSearch } from "@/components/command-search";
import { useToast } from "@/hooks/use-toast";
import { useNotifications, pushNotification } from "@/hooks/use-notifications";

// ─── Audio ping for critical alerts ──────────────────────────────────────────

let _audioCtx: AudioContext | null = null;
function playPing() {
  try {
    if (!_audioCtx) _audioCtx = new AudioContext();
    const osc = _audioCtx.createOscillator();
    const gain = _audioCtx.createGain();
    osc.connect(gain); gain.connect(_audioCtx.destination);
    osc.frequency.value = 880;
    gain.gain.setValueAtTime(0.15, _audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, _audioCtx.currentTime + 0.3);
    osc.start(); osc.stop(_audioCtx.currentTime + 0.3);
  } catch { /* ignore */ }
}

// ─── Page name map ────────────────────────────────────────────────────────────

function pageName(loc: string): string {
  if (loc === "/dashboard") return "Dashboard";
  if (loc.startsWith("/scans/new")) return "New Scan";
  if (loc.startsWith("/scans/compare")) return "Scan Comparison";
  if (loc.startsWith("/scans/")) return "Scan Detail";
  if (loc.startsWith("/scans")) return "Scans";
  if (loc.startsWith("/findings/")) return "Finding Detail";
  if (loc.startsWith("/findings")) return "Findings";
  if (loc.startsWith("/targets/")) return "Target Detail";
  if (loc.startsWith("/targets")) return "Targets";
  if (loc.startsWith("/remediations")) return "Remediations";
  if (loc.startsWith("/system")) return "System";
  if (loc.startsWith("/settings")) return "Settings";
  if (loc.startsWith("/cvss")) return "CVSS Calculator";
  if (loc.startsWith("/audit-log")) return "Audit Log";
  if (loc.startsWith("/executive")) return "Executive Dashboard";
  if (loc.startsWith("/attack-surface")) return "Attack Surface Map";
  if (loc.startsWith("/owasp")) return "OWASP Top 10";
  if (loc.startsWith("/timeline")) return "Activity Timeline";
  if (loc.startsWith("/integrations")) return "Integrations";
  if (loc.startsWith("/scan-templates")) return "Scan Templates";
  if (loc.startsWith("/compliance")) return "Compliance Dashboard";
  if (loc.startsWith("/sla")) return "SLA Tracking";
  if (loc.startsWith("/ai-triage")) return "AI Triage";
  if (loc.startsWith("/admin/users")) return "User Management";
  if (loc.startsWith("/notifications")) return "Notifications";
  return "Dashboard";
}

// ─── Nav ──────────────────────────────────────────────────────────────────────

const NAV_GROUPS = [
  {
    label: "Core",
    items: [
      { href: "/dashboard",    label: "Dashboard",   icon: LayoutDashboard },
      { href: "/scans",        label: "Scans",       icon: Activity },
      { href: "/findings",     label: "Findings",    icon: ShieldAlert },
      { href: "/targets",      label: "Targets",     icon: Target },
      { href: "/remediations", label: "Remediations",icon: CheckSquare },
    ],
  },
  {
    label: "Analytics",
    items: [
      { href: "/executive",      label: "Executive",     icon: TrendingUp },
      { href: "/attack-surface", label: "Attack Surface",icon: Network },
      { href: "/owasp",          label: "OWASP Top 10",  icon: Shield },
      { href: "/timeline",       label: "Timeline",      icon: Clock },
      { href: "/compliance",     label: "Compliance",    icon: ClipboardCheck },
      { href: "/sla",            label: "SLA Tracking",  icon: Timer },
    ],
  },
  {
    label: "AI & Tools",
    items: [
      { href: "/ai-triage",      label: "AI Triage",   icon: Sparkles },
      { href: "/scans/compare",  label: "Scan Compare",icon: GitCompare },
      { href: "/scan-templates", label: "Templates",   icon: Bookmark },
      { href: "/cvss",           label: "CVSS Calc",   icon: Calculator },
    ],
  },
  {
    label: "Config",
    items: [
      { href: "/integrations", label: "Integrations",   icon: Webhook },
      { href: "/audit-log",    label: "Audit Log",       icon: ScrollText },
      { href: "/system",       label: "System",          icon: Cpu },
      { href: "/settings",     label: "Settings",        icon: Settings },
      { href: "/admin/users",  label: "User Management", icon: Shield },
    ],
  },
];

// ─── Severity helpers ─────────────────────────────────────────────────────────

const SEV_DOT: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22d3ee",
};

// ─── Theme cycle ──────────────────────────────────────────────────────────────

const THEMES = ["dark", "light", "high-contrast"] as const;
type Theme = typeof THEMES[number];

function nextTheme(current: string): Theme {
  const idx = THEMES.indexOf(current as Theme);
  return THEMES[(idx + 1) % THEMES.length];
}

function ThemeIcon({ theme }: { theme: string }) {
  if (theme === "light") return <Moon className="w-4 h-4" />;
  if (theme === "high-contrast") return <Contrast className="w-4 h-4" />;
  return <Sun className="w-4 h-4" />;
}

// ─── Notification grouping ────────────────────────────────────────────────────

function groupedPreview(notifications: ReturnType<typeof useNotifications>["notifications"]) {
  // Group by scanId + type for "5 findings from scan #abc"
  const groups: Map<string, typeof notifications> = new Map();
  for (const n of notifications.slice(0, 50)) {
    const key = n.scanId && n.type === "finding" ? `scan-findings-${n.scanId}` : n.id;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(n);
  }
  return [...groups.entries()].map(([key, items]) => ({ key, items, representative: items[0] }));
}

// ─── Layout ───────────────────────────────────────────────────────────────────

export function AppLayout({ children }: { children: React.ReactNode }) {
  const [location, setLocation] = useLocation();
  const { data: user, isLoading: userLoading, isError: userError } = useGetMe({
    query: { retry: false, staleTime: 60000 },
  });
  const { theme, setTheme } = useTheme();
  const { toast } = useToast();
  const { notifications, markRead, markAllRead } = useNotifications();
  const notifRef = useRef<HTMLDivElement>(null);
  const profileRef = useRef<HTMLDivElement>(null);

  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const [cmdOpen, setCmdOpen] = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);
  const [soundMuted, setSoundMuted] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [editProfileOpen, setEditProfileOpen] = useState(false);
  const [profileForm, setProfileForm] = useState({ first_name: "", last_name: "", email: "" });
  const [profileSaving, setProfileSaving] = useState(false);

  const unreadCount = notifications.filter(n => !n.read).length;

  useEffect(() => {
    if (!userLoading && (userError || !user)) setLocation("/login");
  }, [userLoading, userError, user, setLocation]);

  useEffect(() => {
    if (user) {
      const u = user as Record<string, unknown>;
      setProfileForm({
        first_name: (u.first_name as string) ?? "",
        last_name: (u.last_name as string) ?? "",
        email: (u.email as string) ?? "",
      });
    }
  }, [user]);

  // Apply theme class to <html>
  useEffect(() => {
    const html = document.documentElement;
    html.classList.remove("dark", "light", "high-contrast");
    if (theme) html.classList.add(theme);
  }, [theme]);

  // System preference sync on first visit
  useEffect(() => {
    const stored = localStorage.getItem("theme");
    if (!stored) {
      const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      setTheme(prefersDark ? "dark" : "light");
    }
  }, []);

  // Global keyboard shortcuts
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const tag = (e.target as HTMLElement).tagName;
      const inInput = tag === "INPUT" || tag === "TEXTAREA" || (e.target as HTMLElement).isContentEditable;

      if ((e.metaKey || e.ctrlKey) && e.key === "k") { e.preventDefault(); setCmdOpen(o => !o); return; }
      if (inInput) return;
      if (e.key === "n" || e.key === "N") { setLocation("/scans/new"); return; }
      if (e.key === "f" || e.key === "F") { setLocation("/findings"); return; }
      if (e.key === "r" || e.key === "R") { setLocation("/remediations"); return; }
      if (e.key === "t" || e.key === "T") { setTheme(nextTheme(theme ?? "dark")); return; }
      if (e.key === "/") { e.preventDefault(); setCmdOpen(true); return; }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setLocation, theme, setTheme]);

  // Close notif/profile dropdowns on outside click
  useEffect(() => {
    function onClick(e: MouseEvent) {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) setNotifOpen(false);
      if (profileRef.current && !profileRef.current.contains(e.target as Node)) setProfileOpen(false);
    }
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  // SSE subscription for real-time notifications + grouped toasts
  useEffect(() => {
    let active = true;
    const sources: Record<string, EventSource> = {};
    const pendingFindings: Record<string, { count: number; scanId: string; timer: ReturnType<typeof setTimeout> | null }> = {};

    async function pollAndSubscribe() {
      if (!active) return;
      try {
        const res = await fetch("/api/scan-jobs?status=running&page_size=5", { credentials: "include" });
        if (!res.ok) return;
        const data = await res.json() as { items?: Array<{ id: string }> };
        const runningIds = (data.items ?? []).map(s => s.id);

        for (const id of runningIds) {
          if (sources[id]) continue;
          const es = new EventSource(`/api/stream/${id}`, { withCredentials: true } as EventSourceInit);
          sources[id] = es;

          es.onmessage = (ev) => {
            try {
              const d = JSON.parse(ev.data) as Record<string, unknown>;

              if (d["type"] === "finding") {
                const finding = d["finding"] as Record<string, unknown>;
                const sev = String(finding?.["severity"] ?? "");
                if (sev === "critical" || sev === "high") {
                  // Group findings from the same scan into one toast
                  if (!pendingFindings[id]) {
                    pendingFindings[id] = { count: 0, scanId: id, timer: null };
                  }
                  pendingFindings[id].count++;

                  if (pendingFindings[id].timer) clearTimeout(pendingFindings[id].timer!);
                  pendingFindings[id].timer = setTimeout(() => {
                    const { count, scanId } = pendingFindings[id];
                    delete pendingFindings[scanId];

                    const notif = pushNotification({
                      type: "finding",
                      title: count === 1
                        ? `${sev.toUpperCase()} Finding Detected`
                        : `${count} ${sev.toUpperCase()} Findings Detected`,
                      message: count === 1
                        ? String(finding?.["title"] ?? "New vulnerability found")
                        : `${count} new ${sev} findings in scan ${scanId.slice(0, 8)}`,
                      severity: sev,
                      href: `/scans/${scanId}`,
                      scanId,
                      findingId: count === 1 ? String(finding?.["id"] ?? "") : undefined,
                    });

                    if (!soundMuted && sev === "critical") playPing();

                    toast({
                      title: notif.title,
                      description: notif.message,
                      variant: sev === "critical" ? "destructive" : "default",
                      action: (
                        <button
                          onClick={() => setLocation(`/scans/${scanId}`)}
                          className="text-xs underline"
                        >
                          View
                        </button>
                      ) as any,
                    });
                  }, 1500);
                }
              }

              if (d["type"] === "complete") {
                const n = pushNotification({
                  type: "scan_complete",
                  title: "Scan Completed",
                  message: String(d["message"] ?? `Scan ${id.slice(0, 8)} finished`),
                  href: `/scans/${id}`,
                  scanId: id,
                });
                toast({ title: n.title, description: n.message });
                es.close(); delete sources[id];
              }
            } catch { /* ignore */ }
          };
          es.onerror = () => { es.close(); delete sources[id]; };
        }

        for (const id of Object.keys(sources)) {
          if (!runningIds.includes(id)) { sources[id].close(); delete sources[id]; }
        }
      } catch { /* ignore */ }
    }

    const interval = setInterval(pollAndSubscribe, 10000);
    pollAndSubscribe();
    return () => {
      active = false;
      clearInterval(interval);
      Object.values(sources).forEach(es => es.close());
    };
  }, [toast, soundMuted]);

  const currentPage = pageName(location);
  const displayName = (user as Record<string, unknown>)?.github_login as string || (user as Record<string, unknown>)?.username as string || "SecOps Lead";
  const displayRole = ((user as Record<string, unknown>)?.role as string)?.toUpperCase() || "ANALYST";
  const isAdmin = (user as Record<string, unknown>)?.role === "admin";
  const ADMIN_ONLY_PATHS = ["/integrations", "/audit-log", "/admin/users"];

  async function logout() {
    await fetch("/api/auth/logout", { method: "POST", credentials: "include" });
    window.location.href = "/login";
  }

  async function saveProfile() {
    setProfileSaving(true);
    try {
      const r = await fetch("/api/auth/profile", {
        method: "PATCH", credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(profileForm),
      });
      if (!r.ok) throw new Error("Failed");
      toast({ title: "Profile updated" });
      setEditProfileOpen(false);
    } catch {
      toast({ title: "Failed to save profile", variant: "destructive" });
    } finally { setProfileSaving(false); }
  }

  function toggleGroup(label: string) { setCollapsed(p => ({ ...p, [label]: !p[label] })); }

  const grouped = groupedPreview(notifications);

  return (
    <div className="flex h-screen w-full overflow-hidden" style={{ background: "hsl(var(--background))" }}>
      <CommandPalette open={cmdOpen} onClose={() => setCmdOpen(false)} />
      <CommandSearch open={cmdOpen} onClose={() => setCmdOpen(false)} />

      {/* Sidebar */}
      <aside className="flex flex-col border-r" style={{ width: 200, minWidth: 200, background: "hsl(var(--sidebar))", borderColor: "hsl(var(--sidebar-border))" }}>
        <div className="flex items-center gap-3 px-4 py-4 flex-shrink-0">
          <div className="w-8 h-8 rounded-md flex items-center justify-center text-white font-bold text-sm flex-shrink-0"
            style={{ background: "linear-gradient(135deg, #6d28d9, #8b5cf6)" }}>B</div>
          <span className="font-semibold text-sm tracking-tight" style={{ color: "hsl(var(--sidebar-foreground))" }}>Bug Finder Pro</span>
        </div>

        <nav className="flex-1 px-2 py-1 overflow-y-auto space-y-3">
          {NAV_GROUPS.map((group) => {
            const isCollapsed = collapsed[group.label];
            return (
              <div key={group.label}>
                <button onClick={() => toggleGroup(group.label)}
                  className="w-full flex items-center justify-between px-2 py-1 text-[10px] font-semibold uppercase tracking-wider transition-opacity hover:opacity-80"
                  style={{ color: "hsl(var(--muted-foreground))" }}>
                  <span>{group.label}</span>
                  {isCollapsed ? <ChevronRight className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                </button>
                {!isCollapsed && (
                  <div className="space-y-0.5 mt-0.5">
                    {group.items.filter(item =>
                      !ADMIN_ONLY_PATHS.includes(item.href) || isAdmin
                    ).map((item) => {
                      const Icon = item.icon;
                      const active = location === item.href || (item.href !== "/dashboard" && location.startsWith(item.href));
                      return (
                        <Link key={item.href} href={item.href}
                          className="flex items-center gap-3 px-3 py-1.5 rounded-md text-sm transition-all relative"
                          style={active
                            ? { background: "rgba(124,58,237,0.15)", color: "hsl(var(--primary))", borderLeft: "2px solid hsl(var(--primary))", paddingLeft: "10px" }
                            : { color: "hsl(var(--muted-foreground))", borderLeft: "2px solid transparent", paddingLeft: "10px" }}>
                          <Icon className="w-4 h-4 flex-shrink-0" />
                          <span>{item.label}</span>
                        </Link>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </nav>

        <div className="px-3 py-3 border-t flex-shrink-0" style={{ borderColor: "hsl(var(--sidebar-border))" }}>
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0"
              style={{ background: "linear-gradient(135deg, #7c3aed, #ec4899)", color: "white" }}>
              {displayName.slice(0, 2).toUpperCase()}
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-xs font-medium truncate" style={{ color: "hsl(var(--sidebar-foreground))" }}>{displayName}</p>
              <p className="text-[10px] font-mono truncate" style={{ color: "hsl(var(--muted-foreground))" }}>{displayRole}</p>
            </div>
            <button onClick={logout} title="Logout" className="p-1 rounded opacity-50 hover:opacity-100 transition-opacity flex-shrink-0">
              <LogOut className="w-3.5 h-3.5" style={{ color: "hsl(var(--muted-foreground))" }} />
            </button>
          </div>
        </div>
      </aside>

      {/* Main */}
      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-12 flex items-center justify-between px-5 border-b flex-shrink-0"
          style={{ background: "hsl(var(--sidebar))", borderColor: "hsl(var(--border))" }}>
          <div className="flex items-center gap-2 text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>
            <span>Operations</span>
            <span className="opacity-40">›</span>
            <span style={{ color: "hsl(var(--foreground))" }}>{currentPage}</span>
          </div>

          <div className="flex items-center gap-2">
            {/* Search */}
            <button onClick={() => setCmdOpen(true)}
              className="flex items-center gap-2 px-3 py-1.5 rounded-md text-xs transition-colors hover:bg-accent"
              style={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", color: "hsl(var(--muted-foreground))", width: 220 }}>
              <Search className="w-3.5 h-3.5 flex-shrink-0" />
              <span className="flex-1 text-left">Search findings, scans…</span>
              <kbd className="text-[10px] px-1 rounded border font-mono" style={{ borderColor: "hsl(var(--border))" }}>⌘K</kbd>
            </button>

            {/* Theme cycle: Dark → Light → High Contrast → Dark */}
            <button
              onClick={() => setTheme(nextTheme(theme ?? "dark"))}
              className="p-1.5 rounded-md transition-colors hover:bg-accent"
              title={`Theme: ${theme} (T to cycle)`}
              style={{ color: "hsl(var(--muted-foreground))" }}>
              <ThemeIcon theme={theme ?? "dark"} />
            </button>

            {/* Notification bell */}
            <div className="relative" ref={notifRef}>
              <button
                onClick={() => setNotifOpen(o => !o)}
                className="relative p-1.5 rounded-md transition-colors hover:bg-accent"
                style={{ color: "hsl(var(--muted-foreground))" }}>
                <Bell className="w-4 h-4" />
                {unreadCount > 0 && (
                  <span className="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 rounded-full flex items-center justify-center text-[9px] font-bold text-white px-1"
                    style={{ background: "#ef4444" }}>
                    {unreadCount > 9 ? "9+" : unreadCount}
                  </span>
                )}
              </button>

              {notifOpen && (
                <div className="absolute right-0 top-9 w-80 rounded-lg shadow-xl z-50 overflow-hidden"
                  style={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))" }}>
                  <div className="flex items-center justify-between px-4 py-2.5 border-b" style={{ borderColor: "hsl(var(--border))" }}>
                    <span className="text-sm font-semibold">Notifications</span>
                    <div className="flex items-center gap-2">
                      <button onClick={() => setSoundMuted(m => !m)} title={soundMuted ? "Unmute" : "Mute"} className="text-muted-foreground hover:text-foreground">
                        {soundMuted ? <Bell className="w-3 h-3" /> : <Bell className="w-3 h-3" />}
                      </button>
                      {unreadCount > 0 && (
                        <button onClick={markAllRead} className="text-xs text-primary hover:underline">Mark all read</button>
                      )}
                      <button onClick={() => { setNotifOpen(false); setLocation("/notifications"); }}
                        className="text-xs text-muted-foreground hover:text-foreground">
                        <ExternalLink className="w-3 h-3" />
                      </button>
                      <button onClick={() => setNotifOpen(false)}><X className="w-3.5 h-3.5 text-muted-foreground" /></button>
                    </div>
                  </div>

                  <div className="max-h-80 overflow-y-auto">
                    {grouped.length === 0 ? (
                      <div className="px-4 py-6 text-center text-xs text-muted-foreground">No notifications yet</div>
                    ) : grouped.slice(0, 15).map(({ key, items, representative: n }) => (
                      <div key={key}
                        className="px-4 py-3 border-b last:border-0 flex items-start gap-3 transition-colors hover:bg-accent/50 cursor-pointer"
                        style={{ borderColor: "hsl(var(--border))", background: n.read ? "transparent" : "hsl(var(--primary)/0.05)" }}
                        onClick={() => { items.forEach(i => markRead(i.id)); if (n.href) setLocation(n.href); setNotifOpen(false); }}>
                        <div className="w-2 h-2 rounded-full mt-1.5 flex-shrink-0"
                          style={{ background: n.severity ? (SEV_DOT[n.severity] ?? "#6b7280") : "#6b7280" }} />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-medium">
                            {items.length > 1 ? `${items.length}× ${n.title}` : n.title}
                          </p>
                          <p className="text-[11px] text-muted-foreground truncate">{n.message}</p>
                          <p className="text-[10px] text-muted-foreground mt-0.5">{n.time.toLocaleTimeString()}</p>
                        </div>
                        {!n.read && <div className="w-1.5 h-1.5 rounded-full flex-shrink-0 mt-1.5" style={{ background: "#7c3aed" }} />}
                      </div>
                    ))}
                  </div>

                  <div className="px-4 py-2 border-t flex items-center justify-between" style={{ borderColor: "hsl(var(--border))" }}>
                    <button onClick={() => { setLocation("/notifications"); setNotifOpen(false); }}
                      className="text-xs text-primary hover:underline">
                      View all ({notifications.length})
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* Profile dropdown */}
            <div className="relative" ref={profileRef}>
              <button
                onClick={() => setProfileOpen(o => !o)}
                className="flex items-center gap-2 px-2 py-1 rounded-md transition-colors hover:bg-accent"
                style={{ border: "1px solid hsl(var(--border))" }}
              >
                <div className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold flex-shrink-0"
                  style={{ background: "linear-gradient(135deg, #7c3aed, #ec4899)", color: "white" }}>
                  {displayName.slice(0, 2).toUpperCase()}
                </div>
                <span className="text-xs font-medium hidden sm:block" style={{ color: "hsl(var(--foreground))" }}>
                  {displayName}
                </span>
                <ChevronDown className="w-3 h-3" style={{ color: "hsl(var(--muted-foreground))" }} />
              </button>

              {profileOpen && (
                <div className="absolute right-0 top-10 w-72 rounded-lg shadow-xl z-50 overflow-hidden"
                  style={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))" }}>
                  {/* Profile header */}
                  <div className="px-4 py-3 border-b" style={{ borderColor: "hsl(var(--border))" }}>
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0"
                        style={{ background: "linear-gradient(135deg, #7c3aed, #ec4899)", color: "white" }}>
                        {displayName.slice(0, 2).toUpperCase()}
                      </div>
                      <div className="min-w-0">
                        <p className="text-sm font-semibold truncate" style={{ color: "hsl(var(--foreground))" }}>
                          {(user as Record<string, unknown>)?.first_name as string
                            ? `${(user as Record<string, unknown>).first_name} ${(user as Record<string, unknown>).last_name ?? ""}`
                            : displayName}
                        </p>
                        <p className="text-xs truncate" style={{ color: "hsl(var(--muted-foreground))" }}>
                          {(user as Record<string, unknown>)?.email as string ?? ""}
                        </p>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded mt-0.5 inline-block"
                          style={{ background: "hsl(var(--primary)/0.15)", color: "hsl(var(--primary))" }}>
                          {displayRole}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Edit Profile form (inline) */}
                  {editProfileOpen ? (
                    <div className="px-4 py-3 border-b space-y-2" style={{ borderColor: "hsl(var(--border))" }}>
                      <p className="text-xs font-semibold mb-2" style={{ color: "hsl(var(--foreground))" }}>Edit Profile</p>
                      <div className="grid grid-cols-2 gap-2">
                        <input
                          value={profileForm.first_name}
                          onChange={e => setProfileForm(p => ({ ...p, first_name: e.target.value }))}
                          placeholder="First name"
                          className="h-8 px-2 rounded text-xs outline-none w-full"
                          style={{ background: "hsl(var(--muted))", border: "1px solid hsl(var(--border))", color: "hsl(var(--foreground))" }}
                        />
                        <input
                          value={profileForm.last_name}
                          onChange={e => setProfileForm(p => ({ ...p, last_name: e.target.value }))}
                          placeholder="Last name"
                          className="h-8 px-2 rounded text-xs outline-none w-full"
                          style={{ background: "hsl(var(--muted))", border: "1px solid hsl(var(--border))", color: "hsl(var(--foreground))" }}
                        />
                      </div>
                      <input
                        value={profileForm.email}
                        onChange={e => setProfileForm(p => ({ ...p, email: e.target.value }))}
                        placeholder="Email"
                        type="email"
                        className="h-8 px-2 rounded text-xs outline-none w-full"
                        style={{ background: "hsl(var(--muted))", border: "1px solid hsl(var(--border))", color: "hsl(var(--foreground))" }}
                      />
                      <div className="flex gap-2">
                        <button
                          onClick={saveProfile}
                          disabled={profileSaving}
                          className="flex-1 h-7 rounded text-xs font-medium transition-colors"
                          style={{ background: "#7c3aed", color: "white" }}>
                          {profileSaving ? "Saving…" : "Save"}
                        </button>
                        <button
                          onClick={() => setEditProfileOpen(false)}
                          className="flex-1 h-7 rounded text-xs font-medium transition-colors"
                          style={{ background: "hsl(var(--muted))", color: "hsl(var(--muted-foreground))" }}>
                          Cancel
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="py-1">
                      <button
                        onClick={() => setEditProfileOpen(true)}
                        className="w-full flex items-center gap-3 px-4 py-2 text-sm transition-colors hover:bg-accent/50 text-left"
                        style={{ color: "hsl(var(--foreground))" }}>
                        <UserCircle className="w-4 h-4 flex-shrink-0" style={{ color: "hsl(var(--muted-foreground))" }} />
                        Edit Profile
                      </button>
                      <button
                        onClick={() => { setLocation("/settings"); setProfileOpen(false); }}
                        className="w-full flex items-center gap-3 px-4 py-2 text-sm transition-colors hover:bg-accent/50 text-left"
                        style={{ color: "hsl(var(--foreground))" }}>
                        <Settings className="w-4 h-4 flex-shrink-0" style={{ color: "hsl(var(--muted-foreground))" }} />
                        Settings
                      </button>
                      <button
                        onClick={() => { setLocation("/forgot-password"); setProfileOpen(false); }}
                        className="w-full flex items-center gap-3 px-4 py-2 text-sm transition-colors hover:bg-accent/50 text-left"
                        style={{ color: "hsl(var(--foreground))" }}>
                        <KeyRound className="w-4 h-4 flex-shrink-0" style={{ color: "hsl(var(--muted-foreground))" }} />
                        Change Password
                      </button>
                    </div>
                  )}

                  <div className="border-t" style={{ borderColor: "hsl(var(--border))" }}>
                    <button
                      onClick={() => setTheme(nextTheme(theme ?? "dark"))}
                      className="w-full flex items-center gap-3 px-4 py-2 text-sm transition-colors hover:bg-accent/50 text-left"
                      style={{ color: "hsl(var(--foreground))" }}>
                      <ThemeIcon theme={theme ?? "dark"} />
                      <span>Theme: {theme ?? "dark"}</span>
                    </button>
                  </div>

                  <div className="border-t" style={{ borderColor: "hsl(var(--border))" }}>
                    <button
                      onClick={() => { logout(); setProfileOpen(false); }}
                      className="w-full flex items-center gap-3 px-4 py-2 text-sm transition-colors hover:bg-red-500/10 text-left"
                      style={{ color: "#f87171" }}>
                      <LogOut className="w-4 h-4 flex-shrink-0" />
                      Sign Out
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto p-6">
          {children}
        </main>
      </div>
    </div>
  );
}
