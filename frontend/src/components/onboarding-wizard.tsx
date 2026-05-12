import { useState } from "react";
import { useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { CheckCircle, Target, Scan, Shield, Bell, ChevronRight, X } from "lucide-react";

interface OnboardingStep {
  icon: React.ReactNode;
  title: string;
  description: string;
  action?: { label: string; href: string };
}

const STEPS: OnboardingStep[] = [
  {
    icon: <Target className="w-8 h-8 text-primary" />,
    title: "Add Your First Target",
    description: "Start by adding a web application or API endpoint you have authorization to test. Targets track your scan history and risk trends over time.",
    action: { label: "Add Target", href: "/targets" },
  },
  {
    icon: <Scan className="w-8 h-8 text-orange-400" />,
    title: "Run a Quick Scan",
    description: "Launch a Quick Scan (15 modules, ~2 min) to get your first security findings. Quick scans check TLS, headers, cookies, DNS, open ports, and passive recon.",
    action: { label: "New Scan", href: "/scans/new" },
  },
  {
    icon: <Shield className="w-8 h-8 text-red-400" />,
    title: "Review Your Findings",
    description: "Explore discovered vulnerabilities. Use AI analysis for remediation advice, attack chain analysis, and auto-generated code patches for each finding.",
    action: { label: "View Findings", href: "/findings" },
  },
  {
    icon: <Bell className="w-8 h-8 text-yellow-400" />,
    title: "Set Up Alerts",
    description: "Connect Slack or configure webhook integrations to get real-time alerts when critical or high-severity vulnerabilities are discovered during scans.",
    action: { label: "Integrations", href: "/integrations" },
  },
];

const STORAGE_KEY = "bfp_onboarding_dismissed";

export function useOnboarding() {
  const dismissed = typeof window !== "undefined" && localStorage.getItem(STORAGE_KEY) === "true";
  const [show, setShow] = useState(!dismissed);

  function dismiss() {
    localStorage.setItem(STORAGE_KEY, "true");
    setShow(false);
  }

  return { show, dismiss };
}

export function OnboardingWizard({ onDismiss }: { onDismiss: () => void }) {
  const [step, setStep] = useState(0);
  const [, setLocation] = useLocation();

  const current = STEPS[step];
  const isLast = step === STEPS.length - 1;

  function handleAction() {
    if (current.action) {
      setLocation(current.action.href);
      onDismiss();
    }
  }

  function handleNext() {
    if (isLast) {
      onDismiss();
    } else {
      setStep(s => s + 1);
    }
  }

  return (
    <Dialog open onOpenChange={(open) => { if (!open) onDismiss(); }}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center justify-between">
            <span className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-primary" />
              Welcome to Bug Finder Pro
            </span>
            <button
              onClick={onDismiss}
              className="text-muted-foreground hover:text-foreground transition-colors"
              aria-label="Close"
            >
              <X className="w-4 h-4" />
            </button>
          </DialogTitle>
        </DialogHeader>

        {/* Step indicators */}
        <div className="flex gap-2 mb-2">
          {STEPS.map((_, i) => (
            <button
              key={i}
              onClick={() => setStep(i)}
              className={`h-1.5 rounded-full transition-all ${
                i === step ? "bg-primary flex-1" : i < step ? "bg-primary/50 w-6" : "bg-muted w-6"
              }`}
              aria-label={`Step ${i + 1}`}
            />
          ))}
        </div>

        {/* Step content */}
        <div className="flex flex-col items-center text-center py-6 gap-4">
          <div className="p-4 rounded-2xl bg-muted/50 border border-border">
            {current.icon}
          </div>
          <div className="space-y-2">
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Step {step + 1} of {STEPS.length}
            </p>
            <h3 className="text-xl font-semibold">{current.title}</h3>
            <p className="text-sm text-muted-foreground leading-relaxed max-w-sm">
              {current.description}
            </p>
          </div>
        </div>

        {/* Completed steps list */}
        {step > 0 && (
          <div className="space-y-1 mb-2">
            {STEPS.slice(0, step).map((s, i) => (
              <div key={i} className="flex items-center gap-2 text-xs text-muted-foreground">
                <CheckCircle className="w-3.5 h-3.5 text-green-400 shrink-0" />
                {s.title}
              </div>
            ))}
          </div>
        )}

        {/* Actions */}
        <div className="flex items-center gap-3 pt-2">
          {current.action && (
            <Button
              variant="outline"
              size="sm"
              className="flex-1"
              onClick={handleAction}
            >
              {current.action.label}
              <ChevronRight className="w-4 h-4 ml-1" />
            </Button>
          )}
          <Button
            size="sm"
            className="flex-1"
            onClick={handleNext}
          >
            {isLast ? "Get Started" : "Next"}
            {!isLast && <ChevronRight className="w-4 h-4 ml-1" />}
          </Button>
        </div>

        <button
          onClick={onDismiss}
          className="text-xs text-muted-foreground hover:text-foreground text-center w-full mt-1 transition-colors"
        >
          Skip setup guide
        </button>
      </DialogContent>
    </Dialog>
  );
}
