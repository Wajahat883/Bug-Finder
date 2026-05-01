import { Switch, Route, Router as WouterRouter } from "wouter";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/not-found";
import { AppLayout } from "@/components/layout";

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

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, staleTime: 30000 } },
});

function Router() {
  return (
    <Switch>
      <Route path="/" component={Landing} />
      <Route path="/login" component={Login} />
      <Route>
        <AppLayout>
          <Switch>
            <Route path="/dashboard" component={Dashboard} />
            <Route path="/scans" component={Scans} />
            <Route path="/scans/new" component={NewScan} />
            <Route path="/scans/:id" component={ScanDetail} />
            <Route path="/findings" component={Findings} />
            <Route path="/findings/:id" component={FindingDetail} />
            <Route path="/targets" component={Targets} />
            <Route path="/targets/:id" component={TargetDetail} />
            <Route path="/remediations" component={Remediations} />
            <Route path="/system" component={System} />
            <Route path="/settings" component={Settings} />
            <Route path="/cvss" component={CVSSCalculator} />
            <Route path="/audit-log" component={AuditLog} />
            <Route path="/executive" component={Executive} />
            <Route path="/attack-surface" component={AttackSurface} />
            <Route path="/owasp" component={OWASPPage} />
            <Route path="/timeline" component={Timeline} />
            <Route path="/integrations" component={Integrations} />
            <Route component={NotFound} />
          </Switch>
        </AppLayout>
      </Route>
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}>
          <Router />
        </WouterRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
