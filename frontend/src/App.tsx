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
import TestingDashboard from "@/pages/testing";
import AdminLogin from "@/pages/admin-login";
import AdminTenants from "@/pages/admin-tenants";
import CredentialsPage from "@/pages/credentials";
import MetricsDashboard from "@/pages/metrics-dashboard";
import AnalyticsEnhanced from "@/pages/analytics-enhanced";
import Engagements from "@/pages/engagements";
import EngagementDetail from "@/pages/engagement-detail";
import ApiKeysPage from "@/pages/api-keys";
import FalsePositivesPage from "@/pages/false-positives";
import TriageMetricsPage from "@/pages/triage-metrics";
import FeatureFlagsAdmin from "@/pages/feature-flags-admin";
import AdminAnomalyAlerts from "@/pages/admin-anomaly-alerts";
import AdminIpAllowlist from "@/pages/admin-ip-allowlist";
import AdminSessions from "@/pages/admin-sessions";
import AdminSamlConfig from "@/pages/admin-saml-config";
import AdminPolicy from "@/pages/admin-policy";
import Forbidden from "@/pages/forbidden";
import StatusPage from "@/pages/status";
import ReportSchedules from "@/pages/report-schedules";
import SecretsPage from "@/pages/secrets";
import ScannerRulesPage from "@/pages/scanner-rules";
import AdminLoginHistory from "@/pages/admin-login-history";
import SbomPage from "@/pages/sbom";
import ApiDocs from "@/pages/api-docs";

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, staleTime: 30000 } },
});

// Guard for admin-only pages inside AppLayout — redirects to /admin if not admin
function AdminRoute({ component: Component }: { component: React.ComponentType }) {
  const [, nav] = useLocation();
  const { data: user, isLoading } = useGetMe({ query: { retry: false } });
  if (isLoading) return <div className="p-8 text-center text-muted-foreground">Loading…</div>;
  if ((user as Record<string, unknown>)?.role !== "admin") {
    nav("/forbidden");
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
            <Route path="/system">
              {() => <AdminRoute component={System} />}
            </Route>
            <Route path="/settings" component={Settings} />
            <Route path="/notifications" component={Notifications} />
            <Route path="/security" component={TwoFactor} />
            <Route path="/scheduled-scans" component={ScheduledScans} />

            {/* ── Analytics — Admin-only routes ── */}
            <Route path="/cvss">
              {() => <AdminRoute component={CVSSCalculator} />}
            </Route>
            <Route path="/executive">
              {() => <AdminRoute component={Executive} />}
            </Route>
            <Route path="/attack-surface">
              {() => <AdminRoute component={AttackSurface} />}
            </Route>
            <Route path="/scan-templates">
              {() => <AdminRoute component={ScanTemplates} />}
            </Route>
            <Route path="/compliance">
              {() => <AdminRoute component={ComplianceDashboard} />}
            </Route>
            <Route path="/sla">
              {() => <AdminRoute component={SlaDashboard} />}
            </Route>
            <Route path="/engagements/:id">
              {() => <AdminRoute component={EngagementDetail} />}
            </Route>
            <Route path="/engagements">
              {() => <AdminRoute component={Engagements} />}
            </Route>
            <Route path="/owasp" component={OWASPPage} />
            <Route path="/timeline" component={Timeline} />
            <Route path="/metrics" component={MetricsDashboard} />
            <Route path="/analytics-enhanced" component={AnalyticsEnhanced} />
            <Route path="/ai-triage" component={AiTriage} />
            <Route path="/false-positives" component={FalsePositivesPage} />
            <Route path="/triage-metrics" component={TriageMetricsPage} />
            <Route path="/feature-flags">
              {() => <AdminRoute component={FeatureFlagsAdmin} />}
            </Route>

            {/* ── Admin-only routes ── */}
            <Route path="/testing">
              {() => <AdminRoute component={TestingDashboard} />}
            </Route>
            <Route path="/api-keys">
              {() => <AdminRoute component={ApiKeysPage} />}
            </Route>
            <Route path="/admin/panel">
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
            <Route path="/admin/anomaly-alerts">
              {() => <AdminRoute component={AdminAnomalyAlerts} />}
            </Route>
            <Route path="/admin/ip-allowlist">
              {() => <AdminRoute component={AdminIpAllowlist} />}
            </Route>
            <Route path="/admin/sessions">
              {() => <AdminRoute component={AdminSessions} />}
            </Route>
            <Route path="/admin/saml-config">
              {() => <AdminRoute component={AdminSamlConfig} />}
            </Route>
            <Route path="/admin/policy">
              {() => <AdminRoute component={AdminPolicy} />}
            </Route>
            <Route path="/admin/tenants">
              {() => <AdminRoute component={AdminTenants} />}
            </Route>
            <Route path="/credentials" component={CredentialsPage} />
            <Route path="/secrets" component={SecretsPage} />
            <Route path="/scanner-rules" component={ScannerRulesPage} />
            <Route path="/admin/login-history">
              {() => <AdminRoute component={AdminLoginHistory} />}
            </Route>

            <Route path="/scans/:id/sbom" component={SbomPage} />
            <Route path="/api-docs" component={ApiDocs} />
            <Route path="/report-schedules" component={ReportSchedules} />
            <Route path="/status" component={StatusPage} />
            <Route path="/forbidden" component={Forbidden} />
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
