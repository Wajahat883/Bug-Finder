import { Switch, Route, Router as WouterRouter, useLocation } from "wouter";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ThemeProvider } from "next-themes";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/not-found";
import { AppLayout } from "@/components/layout";
import { ErrorBoundary } from "@/components/error-boundary";
import { useGetMe } from "@/api-client";

import Landing from "@/pages/landing";
import Dashboard from "@/pages/dashboard";
import Scans from "@/pages/scans";
import NewScan from "@/pages/new-scan";
import ScanDetail from "@/pages/scan-detail";
import Findings from "@/pages/findings";
import FindingDetail from "@/pages/finding-detail";
import Targets from "@/pages/targets";
import TargetDetail from "@/pages/target-detail";
import Remediations from "@/pages/remediations";
import System from "@/pages/system";
import Settings from "@/pages/settings";
import Login from "@/pages/login";
import CVSSCalculator from "@/pages/cvss";
import AuditLog from "@/pages/audit-log";
import Executive from "@/pages/executive";
import AttackSurface from "@/pages/attack-surface";
import OWASPPage from "@/pages/owasp";
import Timeline from "@/pages/timeline";
import Integrations from "@/pages/integrations";
import ScanTemplates from "@/pages/scan-templates";
import ScanCompare from "@/pages/scan-compare";
import ComplianceDashboard from "@/pages/compliance-dashboard";
import SlaDashboard from "@/pages/sla-dashboard";
import AiTriage from "@/pages/ai-triage";
import ForgotPassword from "@/pages/forgot-password";
import ResetPassword from "@/pages/reset-password";
import AdminUsers from "@/pages/admin-users";
import AdminPanel from "@/pages/admin-panel";
import Notifications from "@/pages/notifications";
import TwoFactor from "@/pages/two-factor";
import ScheduledScans from "@/pages/scheduled-scans";
import AdminLogin from "@/pages/admin-login";

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, staleTime: 30000 } },
});

// Guard for admin-only pages inside AppLayout — redirects to /admin if not admin
function AdminRoute({ component: Component }: { component: React.ComponentType }) {
  const [, nav] = useLocation();
  const { data: user, isLoading } = useGetMe({ query: { retry: false } });
  if (isLoading) return <div className="p-8 text-center text-muted-foreground">Loading…</div>;
  if ((user as Record<string, unknown>)?.role !== "admin") {
    nav("/admin");
    return null;
  }
  return <Component />;
}

function Router() {
  return (
    <Switch>
      {/* ── Public routes (no layout) ── */}
      <Route path="/" component={Landing} />

      {/* User login — /login */}
      <Route path="/login" component={Login} />

      {/* Admin login — /admin (completely separate from /login) */}
      <Route path="/admin" component={AdminLogin} />

      <Route path="/forgot-password" component={ForgotPassword} />
      <Route path="/reset-password" component={ResetPassword} />

      {/* ── Authenticated routes (inside AppLayout) ── */}
      <Route>
        <AppLayout>
          <Switch>
            <Route path="/dashboard" component={Dashboard} />
            <Route path="/scans/new" component={NewScan} />
            <Route path="/scans/compare" component={ScanCompare} />
            <Route path="/scans/:id" component={ScanDetail} />
            <Route path="/scans" component={Scans} />
            <Route path="/findings/:id" component={FindingDetail} />
            <Route path="/findings" component={Findings} />
            <Route path="/targets/:id" component={TargetDetail} />
            <Route path="/targets" component={Targets} />
            <Route path="/remediations" component={Remediations} />
            <Route path="/system" component={System} />
            <Route path="/settings" component={Settings} />
            <Route path="/cvss" component={CVSSCalculator} />
            <Route path="/executive" component={Executive} />
            <Route path="/attack-surface" component={AttackSurface} />
            <Route path="/owasp" component={OWASPPage} />
            <Route path="/timeline" component={Timeline} />
            <Route path="/scan-templates" component={ScanTemplates} />
            <Route path="/compliance" component={ComplianceDashboard} />
            <Route path="/sla" component={SlaDashboard} />
            <Route path="/ai-triage" component={AiTriage} />
            <Route path="/notifications" component={Notifications} />
            <Route path="/security" component={TwoFactor} />
            <Route path="/scheduled-scans" component={ScheduledScans} />

            {/* ── Admin-only routes ── */}
            <Route path="/adminW">
              {() => <AdminRoute component={AdminPanel} />}
            </Route>
            <Route path="/audit-log">
              {() => <AdminRoute component={AuditLog} />}
            </Route>
            <Route path="/integrations">
              {() => <AdminRoute component={Integrations} />}
            </Route>
            <Route path="/admin/users">
              {() => <AdminRoute component={AdminUsers} />}
            </Route>

            <Route component={NotFound} />
          </Switch>
        </AppLayout>
      </Route>
    </Switch>
  );
}

function App() {
  return (
    <ThemeProvider attribute="class" defaultTheme="dark" enableSystem themes={["dark", "light", "high-contrast"]}>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}>
            <ErrorBoundary>
              <Router />
            </ErrorBoundary>
          </WouterRouter>
          <Toaster />
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>
  );
}

export default App;
