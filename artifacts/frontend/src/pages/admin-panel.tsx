import { useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Shield, Users, ScrollText, Webhook, Settings, ArrowRight,
  Activity, Lock, AlertTriangle, BarChart3,
} from "lucide-react";

interface DashboardStats {
  totalUsers: number;
  totalScans: number;
  totalFindings: number;
  activeScans: number;
}

export default function AdminPanel() {
  const [, setLocation] = useLocation();

  const { data: stats, isLoading } = useQuery<DashboardStats>({
    queryKey: ["/api/admin/stats"],
    queryFn: () =>
      fetch("/api/admin/stats", { credentials: "include" }).then(r => {
        if (!r.ok) throw new Error("Unauthorized");
        return r.json();
      }),
    staleTime: 30000,
  });

  const adminModules = [
    {
      title: "User Management",
      description: "Manage platform users, roles, and account status.",
      icon: Users,
      href: "/admin/users",
      color: "#8b5cf6",
      bg: "rgba(139,92,246,0.1)",
    },
    {
      title: "Audit Log",
      description: "Security audit trail with user actions and events.",
      icon: ScrollText,
      href: "/audit-log",
      color: "#22d3ee",
      bg: "rgba(34,211,238,0.1)",
    },
    {
      title: "Integrations",
      description: "Configure GitHub, Slack, webhooks, and API keys.",
      icon: Webhook,
      href: "/integrations",
      color: "#f97316",
      bg: "rgba(249,115,22,0.1)",
    },
    {
      title: "Platform Settings",
      description: "Global configuration, AI models, and SMTP.",
      icon: Settings,
      href: "/settings",
      color: "#34d399",
      bg: "rgba(52,211,153,0.1)",
    },
  ];

  const quickStats = [
    { label: "Total Users", value: stats?.totalUsers ?? 0, icon: Users, color: "#8b5cf6" },
    { label: "Total Scans", value: stats?.totalScans ?? 0, icon: Activity, color: "#22d3ee" },
    { label: "Total Findings", value: stats?.totalFindings ?? 0, icon: AlertTriangle, color: "#f97316" },
    { label: "Active Scans", value: stats?.activeScans ?? 0, icon: BarChart3, color: "#34d399" },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
            <Shield className="w-7 h-7 text-purple-400" />
            Admin Panel
          </h1>
          <p className="text-muted-foreground mt-1">
            Central dashboard for platform administration and oversight.
          </p>
        </div>
        <Badge variant="outline" className="text-[10px] uppercase font-bold bg-purple-500/10 text-purple-400 border-purple-500/30">
          <Lock className="w-3 h-3 mr-1" />
          Admin Access
        </Badge>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {quickStats.map((stat) => {
          const Icon = stat.icon;
          return (
            <Card key={stat.label} className="border-border/60">
              <CardContent className="p-5">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs text-muted-foreground uppercase font-semibold tracking-wider">
                      {stat.label}
                    </p>
                    <p className="text-2xl font-bold mt-1">
                      {isLoading ? "—" : stat.value}
                    </p>
                  </div>
                  <div
                    className="w-10 h-10 rounded-lg flex items-center justify-center"
                    style={{ background: stat.color + "15" }}
                  >
                    <Icon className="w-5 h-5" style={{ color: stat.color }} />
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Admin Modules Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {adminModules.map((mod) => {
          const Icon = mod.icon;
          return (
            <Card
              key={mod.title}
              className="border-border/60 hover:border-border transition-colors cursor-pointer group"
              onClick={() => setLocation(mod.href)}
            >
              <CardContent className="p-5">
                <div className="flex items-start gap-4">
                  <div
                    className="w-11 h-11 rounded-xl flex items-center justify-center flex-shrink-0"
                    style={{ background: mod.bg }}
                  >
                    <Icon className="w-5 h-5" style={{ color: mod.color }} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <h3 className="font-semibold text-sm">{mod.title}</h3>
                      <ArrowRight
                        className="w-4 h-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity"
                      />
                    </div>
                    <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                      {mod.description}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Info Banner */}
      <div
        className="flex items-start gap-3 rounded-xl px-4 py-3 text-xs"
        style={{
          background: "rgba(220,38,38,0.06)",
          border: "1px solid rgba(220,38,38,0.15)",
        }}
      >
        <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" style={{ color: "#f87171" }} />
        <div style={{ color: "rgba(248,113,113,0.85)" }}>
          <span className="font-semibold">Security Notice:</span> All admin actions are logged to the audit trail.
          Ensure you have proper authorisation before making changes to user roles or platform settings.
        </div>
      </div>
    </div>
  );
}
