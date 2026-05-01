import { Switch, Route, Router as WouterRouter } from "wouter";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/not-found";
import { AppLayout } from "@/components/layout";

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

const queryClient = new QueryClient();

function Router() {
  return (
    <AppLayout>
      <Switch>
        <Route path="/" component={Dashboard} />
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
        <Route component={NotFound} />
      </Switch>
    </AppLayout>
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
