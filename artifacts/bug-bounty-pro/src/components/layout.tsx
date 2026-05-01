import { Link, useLocation } from "wouter";
import { useGetMe, useLogout } from "@workspace/api-client-react";
import { Activity, LayoutDashboard, Search, Shield, Target, Settings, Settings2, ShieldAlert, LogOut, CheckSquare } from "lucide-react";
import { Button } from "./ui/button";

export function AppLayout({ children }: { children: React.ReactNode }) {
  const [location] = useLocation();
  const { data: user } = useGetMe();
  const logout = useLogout();

  const handleLogout = () => {
    logout.mutate(undefined, {
      onSuccess: () => window.location.reload()
    });
  };

  const navItems = [
    { href: "/", label: "Dashboard", icon: LayoutDashboard },
    { href: "/scans", label: "Scans", icon: Activity },
    { href: "/findings", label: "Findings", icon: ShieldAlert },
    { href: "/targets", label: "Targets", icon: Target },
    { href: "/remediations", label: "Remediations", icon: CheckSquare },
    { href: "/system", label: "System", icon: Shield },
    { href: "/settings", label: "Settings", icon: Settings },
  ];

  return (
    <div className="flex h-screen w-full bg-background overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 border-r border-border bg-card flex flex-col">
        <div className="h-14 flex items-center px-4 border-b border-border">
          <Shield className="w-5 h-5 text-primary mr-2" />
          <span className="font-bold text-foreground tracking-tight">BugBounty Pro</span>
        </div>
        
        <nav className="flex-1 py-4 px-2 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = location === item.href || (item.href !== "/" && location.startsWith(item.href));
            return (
              <Link key={item.href} href={item.href} className={`flex items-center px-3 py-2 text-sm font-medium rounded-md transition-colors ${active ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-muted hover:text-foreground"}`}>
                <Icon className="w-4 h-4 mr-3" />
                {item.label}
              </Link>
            );
          })}
        </nav>

        <div className="p-4 border-t border-border">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center text-primary font-bold">
                {user?.username?.charAt(0).toUpperCase() || "U"}
              </div>
              <div className="flex flex-col">
                <span className="text-sm font-medium text-foreground">{user?.username || "Operator"}</span>
                <span className="text-xs text-muted-foreground capitalize">{user?.role || "Admin"}</span>
              </div>
            </div>
            <Button variant="ghost" size="icon" onClick={handleLogout} title="Logout">
              <LogOut className="w-4 h-4 text-muted-foreground" />
            </Button>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-14 border-b border-border bg-card/50 backdrop-blur flex items-center justify-between px-6">
          <div className="flex items-center bg-muted/50 border border-border rounded-md px-3 py-1.5 w-96">
            <Search className="w-4 h-4 text-muted-foreground mr-2" />
            <input 
              type="text" 
              placeholder="Search scans, targets, findings..." 
              className="bg-transparent border-none outline-none text-sm text-foreground w-full placeholder:text-muted-foreground"
            />
          </div>
          
          <div className="flex items-center space-x-2">
            <Button variant="outline" size="sm" className="hidden md:flex">
              <Settings2 className="w-4 h-4 mr-2" />
              Command Palette
            </Button>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto p-6">
          {children}
        </main>
      </div>
    </div>
  );
}
