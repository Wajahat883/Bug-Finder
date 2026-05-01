import { Link, useLocation } from "wouter";
import { useGetMe } from "@workspace/api-client-react";
import {
  Activity, LayoutDashboard, Search, Target, ShieldAlert,
  Bell, CheckSquare, Shield, Settings, Cpu,
} from "lucide-react";

function pageName(loc: string): string {
  if (loc === "/") return "Dashboard";
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
  return "Dashboard";
}

export function AppLayout({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();
  const { data: user } = useGetMe();

  const navItems = [
    { href: "/", label: "Dashboard", icon: LayoutDashboard },
    { href: "/scans", label: "Scans", icon: Activity },
    { href: "/findings", label: "Findings", icon: ShieldAlert },
    { href: "/targets", label: "Targets", icon: Target },
    { href: "/remediations", label: "Remediations", icon: CheckSquare },
    { href: "/system", label: "System", icon: Cpu },
    { href: "/settings", label: "Settings", icon: Settings },
  ];

  const currentPage = pageName(location);
  const displayName = (user as any)?.github_login || (user as any)?.username || "SecOps Lead";
  const displayRole = (user as any)?.role?.toUpperCase() || "PRO-ENV-01";

  return (
    <div className="flex h-screen w-full overflow-hidden" style={{ background: "hsl(var(--background))" }}>
      {/* Sidebar */}
      <aside
        className="flex flex-col border-r"
        style={{
          width: 192,
          minWidth: 192,
          background: "hsl(var(--sidebar))",
          borderColor: "hsl(var(--sidebar-border))",
        }}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-4 py-4">
          <div
            className="w-8 h-8 rounded-md flex items-center justify-center text-white font-bold text-sm flex-shrink-0"
            style={{ background: "linear-gradient(135deg, #6d28d9, #8b5cf6)" }}
          >
            B
          </div>
          <span className="font-semibold text-sm tracking-tight" style={{ color: "hsl(var(--sidebar-foreground))" }}>
            Bug Bounty Pro
          </span>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-2 py-2 space-y-0.5 overflow-y-auto">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active =
              location === item.href ||
              (item.href !== "/" && location.startsWith(item.href));
            return (
              <Link
                key={item.href}
                href={item.href}
                className="flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-all relative"
                style={
                  active
                    ? {
                        background: "rgba(124, 58, 237, 0.15)",
                        color: "hsl(var(--primary))",
                        borderLeft: "2px solid hsl(var(--primary))",
                        paddingLeft: "10px",
                      }
                    : {
                        color: "hsl(var(--muted-foreground))",
                        borderLeft: "2px solid transparent",
                        paddingLeft: "10px",
                      }
                }
              >
                <Icon className="w-4 h-4 flex-shrink-0" />
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>

        {/* User footer */}
        <div
          className="px-3 py-3 border-t flex items-center gap-3"
          style={{ borderColor: "hsl(var(--sidebar-border))" }}
        >
          <div
            className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0"
            style={{ background: "linear-gradient(135deg, #7c3aed, #ec4899)", color: "white" }}
          >
            {displayName.slice(0, 2).toUpperCase()}
          </div>
          <div className="min-w-0">
            <p className="text-xs font-medium truncate" style={{ color: "hsl(var(--sidebar-foreground))" }}>
              {displayName}
            </p>
            <p className="text-[10px] font-mono truncate" style={{ color: "hsl(var(--muted-foreground))" }}>
              {displayRole}
            </p>
          </div>
        </div>
      </aside>

      {/* Main */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top header */}
        <header
          className="h-12 flex items-center justify-between px-5 border-b flex-shrink-0"
          style={{
            background: "hsl(var(--sidebar))",
            borderColor: "hsl(var(--border))",
          }}
        >
          {/* Breadcrumb */}
          <div className="flex items-center gap-2 text-xs" style={{ color: "hsl(var(--muted-foreground))" }}>
            <span>Operations</span>
            <span className="opacity-40">›</span>
            <span style={{ color: "hsl(var(--foreground))" }}>{currentPage}</span>
          </div>

          {/* Search + controls */}
          <div className="flex items-center gap-3">
            <div
              className="flex items-center gap-2 px-3 py-1.5 rounded-md text-xs"
              style={{
                background: "hsl(var(--card))",
                border: "1px solid hsl(var(--border))",
                color: "hsl(var(--muted-foreground))",
                width: 240,
              }}
            >
              <Search className="w-3.5 h-3.5 flex-shrink-0" />
              <input
                type="text"
                placeholder="Search endpoints, findings, IDs..."
                className="bg-transparent border-none outline-none text-xs w-full placeholder:text-muted-foreground"
              />
              <kbd
                className="ml-auto text-[10px] px-1 rounded hidden sm:flex"
                style={{ background: "hsl(var(--muted))", color: "hsl(var(--muted-foreground))" }}
              >
                ⌘K
              </kbd>
            </div>

            {/* Bell */}
            <button
              className="relative p-1.5 rounded-md transition-colors"
              style={{ color: "hsl(var(--muted-foreground))" }}
            >
              <Bell className="w-4 h-4" />
              <span
                className="absolute top-0.5 right-0.5 w-1.5 h-1.5 rounded-full"
                style={{ background: "hsl(var(--primary))" }}
              />
            </button>

            {/* AUTH status */}
            <div
              className="flex items-center gap-1.5 text-[10px] font-mono px-2 py-1 rounded border"
              style={{
                background: "hsl(var(--card))",
                borderColor: "hsl(var(--border))",
                color: "#4ade80",
              }}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
              AUTH: OK
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
