import { Link, useLocation } from "wouter";
import { useGetMe } from "@workspace/api-client-react";
import {
  Activity, LayoutDashboard, Search, Target, ShieldAlert,
  Bell, CheckSquare, Shield, Settings, Cpu, ScrollText,
  Calculator, Network, TrendingUp, Clock, Webhook, LogOut,
  ChevronDown, ChevronRight,
} from "lucide-react";
import { useState, useEffect } from "react";

function pageName(loc: string): string {
  if (loc === "/dashboard") return "Dashboard";
  if (loc.startsWith("/scans/new")) return "New Scan";
  if (loc.startsWith("/scans/")) return "Scan Detail";
  if (loc.startsWith("/scans")) return "Scans";
  if (loc.startsWith("/findings/")) return "Finding Detail";
  if (loc.startsWith("/findings")) return "Findings";
  if (loc.startsWith("/targets/")) return "Target Detail";
  if (loc.startsWith("/targets")) return "Targets";
  if (loc.startsWith("/remediations")) return "Remediations";
  if (loc.startsWith("/system")) return "System";
  if (loc.startsWith("/settings")) return "Settings";
  if (loc.startsWith("/login")) return "Login";
  if (loc.startsWith("/cvss")) return "CVSS Calculator";
  if (loc.startsWith("/audit-log")) return "Audit Log";
  if (loc.startsWith("/executive")) return "Executive Dashboard";
  if (loc.startsWith("/attack-surface")) return "Attack Surface Map";
  if (loc.startsWith("/owasp")) return "OWASP Top 10";
  if (loc.startsWith("/timeline")) return "Activity Timeline";
  if (loc.startsWith("/integrations")) return "Integrations";
  return "Dashboard";
}

const NAV_GROUPS = [
  {
    label: "Core",
    items: [
      { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
      { href: "/scans", label: "Scans", icon: Activity },
      { href: "/findings", label: "Findings", icon: ShieldAlert },
      { href: "/targets", label: "Targets", icon: Target },
      { href: "/remediations", label: "Remediations", icon: CheckSquare },
    ],
  },
  {
    label: "Analytics",
    items: [
      { href: "/executive", label: "Executive", icon: TrendingUp },
      { href: "/attack-surface", label: "Attack Surface", icon: Network },
      { href: "/owasp", label: "OWASP Top 10", icon: Shield },
      { href: "/timeline", label: "Timeline", icon: Clock },
    ],
  },
  {
    label: "Tools",
    items: [
      { href: "/cvss", label: "CVSS Calc", icon: Calculator },
      { href: "/integrations", label: "Integrations", icon: Webhook },
      { href: "/audit-log", label: "Audit Log", icon: ScrollText },
    ],
  },
  {
    label: "System",
    items: [
      { href: "/system", label: "System", icon: Cpu },
      { href: "/settings", label: "Settings", icon: Settings },
    ],
  },
];

export function AppLayout({ children }: { children: React.ReactNode }) {
  const [location, setLocation] = useLocation();
  const { data: user, isLoading: userLoading, isError: userError } = useGetMe({
    query: { retry: false, staleTime: 60000 },
  });

  useEffect(() => {
    if (!userLoading && (userError || !user)) {
      setLocation("/login");
    }
  }, [userLoading, userError, user, setLocation]);

  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  const currentPage = pageName(location);
  const displayName = (user as Record<string, unknown>)?.github_login as string || (user as Record<string, unknown>)?.username as string || "SecOps Lead";
  const displayRole = ((user as Record<string, unknown>)?.role as string)?.toUpperCase() || "ANALYST";

  async function logout() {
    await fetch("/api/auth/logout", { method: "POST", credentials: "include" });
    window.location.href = "/login";
  }

  function toggleGroup(label: string) {
    setCollapsed(p => ({ ...p, [label]: !p[label] }));
  }

  return (
    <div className="flex h-screen w-full overflow-hidden" style={{ background: "hsl(var(--background))" }}>
      <aside className="flex flex-col border-r" style={{ width: 200, minWidth: 200, background: "hsl(var(--sidebar))", borderColor: "hsl(var(--sidebar-border))" }}>
        <div className="flex items-center gap-3 px-4 py-4 flex-shrink-0">
          <div className="w-8 h-8 rounded-md flex items-center justify-center text-white font-bold text-sm flex-shrink-0"
            style={{ background: "linear-gradient(135deg, #6d28d9, #8b5cf6)" }}>B</div>
          <span className="font-semibold text-sm tracking-tight" style={{ color: "hsl(var(--sidebar-foreground))" }}>Bug Finder Pro</span>
        </div>

        <nav className="flex-1 px-2 py-1 overflow-y-auto space-y-3">
          {NAV_GROUPS.map(group => {
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
                    {group.items.map(item => {
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

      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-12 flex items-center justify-between px-5 border-b flex-shrink-0"
          style={{ background: "hsl(var(--sidebar))", borderColor: "hsl(var(--border))" }}>
          <div className="flex items-center gap-2 text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>
            <span>Operations</span>
            <span className="opacity-40">›</span>
            <span style={{ color: "hsl(var(--foreground))" }}>{currentPage}</span>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-md text-xs"
              style={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", color: "hsl(var(--muted-foreground))", width: 220 }}>
              <Search className="w-3.5 h-3.5 flex-shrink-0" />
              <input type="text" placeholder="Search findings, scans, targets..."
                className="bg-transparent border-none outline-none text-xs w-full placeholder:text-muted-foreground" />
            </div>
            <button className="relative p-1.5 rounded-md transition-colors" style={{ color: "hsl(var(--muted-foreground))" }}>
              <Bell className="w-4 h-4" />
              <span className="absolute top-0.5 right-0.5 w-1.5 h-1.5 rounded-full" style={{ background: "hsl(var(--primary))" }} />
            </button>
            <div className="flex items-center gap-1.5 text-[10px] font-mono px-2 py-1 rounded border"
              style={{ background: "hsl(var(--card))", borderColor: "hsl(var(--border))", color: "#4ade80" }}>
              <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
              AUTH: OK
            </div>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto">
          {children}
        </main>
      </div>
    </div>
  );
}
