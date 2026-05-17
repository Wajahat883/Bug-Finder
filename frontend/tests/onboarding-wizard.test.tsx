import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { Router as WouterRouter } from "wouter";
import React from "react";

// Mock wouter's useLocation so navigation calls don't crash
const mockSetLocation = vi.fn();
vi.mock("wouter", async (importOriginal) => {
  const actual = await importOriginal<typeof import("wouter")>();
  return {
    ...actual,
    useLocation: vi.fn(() => ["/dashboard", mockSetLocation]),
  };
});

function renderWizard(props: { onDismiss?: () => void; onComplete?: () => void } = {}) {
  // WouterRouter is needed for any internal Link usage
  return render(
    <WouterRouter base="">
      {React.createElement(
        // Lazy import workaround — we import inline in each test to avoid module cache issues
        // This wrapper only provides routing context
        React.Fragment,
        null,
        React.createElement(React.Suspense, { fallback: null })
      )}
    </WouterRouter>
  );
}

describe("OnboardingWizard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Clear localStorage so wizard always starts fresh
    localStorage.clear();
  });

  it("renders the first step title and description", async () => {
    const { OnboardingWizard } = await import("@/components/onboarding-wizard");
    render(
      <WouterRouter base="">
        <OnboardingWizard />
      </WouterRouter>
    );
    expect(screen.getByText(/add your first target/i)).toBeInTheDocument();
    expect(screen.getByText(/step 1 of 4/i)).toBeInTheDocument();
  });

  it("shows the welcome header", async () => {
    const { OnboardingWizard } = await import("@/components/onboarding-wizard");
    render(
      <WouterRouter base="">
        <OnboardingWizard />
      </WouterRouter>
    );
    expect(screen.getByText(/welcome to bug finder pro/i)).toBeInTheDocument();
  });

  it("shows step progress indicators for all 4 steps", async () => {
    const { OnboardingWizard } = await import("@/components/onboarding-wizard");
    render(
      <WouterRouter base="">
        <OnboardingWizard />
      </WouterRouter>
    );
    // Each step indicator has aria-label "Step N"
    expect(screen.getByLabelText("Step 1")).toBeInTheDocument();
    expect(screen.getByLabelText("Step 2")).toBeInTheDocument();
    expect(screen.getByLabelText("Step 3")).toBeInTheDocument();
    expect(screen.getByLabelText("Step 4")).toBeInTheDocument();
  });

  it("advances to step 2 when 'Next' is clicked", async () => {
    const { OnboardingWizard } = await import("@/components/onboarding-wizard");
    render(
      <WouterRouter base="">
        <OnboardingWizard />
      </WouterRouter>
    );
    fireEvent.click(screen.getByRole("button", { name: /^next/i }));
    expect(screen.getByText(/run a quick scan/i)).toBeInTheDocument();
    expect(screen.getByText(/step 2 of 4/i)).toBeInTheDocument();
  });

  it("advances through all 4 steps in order", async () => {
    const { OnboardingWizard } = await import("@/components/onboarding-wizard");
    render(
      <WouterRouter base="">
        <OnboardingWizard />
      </WouterRouter>
    );

    // Step 1 -> 2
    fireEvent.click(screen.getByRole("button", { name: /^next/i }));
    expect(screen.getByText(/step 2 of 4/i)).toBeInTheDocument();

    // Step 2 -> 3
    fireEvent.click(screen.getByRole("button", { name: /^next/i }));
    expect(screen.getByText(/step 3 of 4/i)).toBeInTheDocument();

    // Step 3 -> 4
    fireEvent.click(screen.getByRole("button", { name: /^next/i }));
    expect(screen.getByText(/step 4 of 4/i)).toBeInTheDocument();
  });

  it("shows 'Get Started' instead of 'Next' on the last step", async () => {
    const { OnboardingWizard } = await import("@/components/onboarding-wizard");
    render(
      <WouterRouter base="">
        <OnboardingWizard />
      </WouterRouter>
    );
    // Navigate to last step (step 4)
    fireEvent.click(screen.getByRole("button", { name: /^next/i }));
    fireEvent.click(screen.getByRole("button", { name: /^next/i }));
    fireEvent.click(screen.getByRole("button", { name: /^next/i }));

    expect(screen.getByRole("button", { name: /get started/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^next/i })).not.toBeInTheDocument();
  });

  it("calls onDismiss when 'Skip setup guide' is clicked", async () => {
    const { OnboardingWizard } = await import("@/components/onboarding-wizard");
    const onDismiss = vi.fn();
    render(
      <WouterRouter base="">
        <OnboardingWizard onDismiss={onDismiss} />
      </WouterRouter>
    );
    fireEvent.click(screen.getByText(/skip setup guide/i));
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it("calls onDismiss when the X close button is clicked", async () => {
    const { OnboardingWizard } = await import("@/components/onboarding-wizard");
    const onDismiss = vi.fn();
    render(
      <WouterRouter base="">
        <OnboardingWizard onDismiss={onDismiss} />
      </WouterRouter>
    );
    // The wizard renders its own X button (aria-label="Close") plus Radix UI
    // adds a second sr-only Close button. Click the first one (our custom X).
    const closeButtons = screen.getAllByRole("button", { name: /close/i });
    fireEvent.click(closeButtons[0]);
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it("calls onComplete when 'Get Started' is clicked on last step", async () => {
    const { OnboardingWizard } = await import("@/components/onboarding-wizard");
    const onComplete = vi.fn();
    render(
      <WouterRouter base="">
        <OnboardingWizard onComplete={onComplete} />
      </WouterRouter>
    );
    // Navigate to last step
    fireEvent.click(screen.getByRole("button", { name: /^next/i }));
    fireEvent.click(screen.getByRole("button", { name: /^next/i }));
    fireEvent.click(screen.getByRole("button", { name: /^next/i }));

    fireEvent.click(screen.getByRole("button", { name: /get started/i }));
    expect(onComplete).toHaveBeenCalledTimes(1);
  });

  it("shows completed step titles as the user advances", async () => {
    const { OnboardingWizard } = await import("@/components/onboarding-wizard");
    render(
      <WouterRouter base="">
        <OnboardingWizard />
      </WouterRouter>
    );
    // Advance to step 2
    fireEvent.click(screen.getByRole("button", { name: /^next/i }));
    // Step 1 title should appear in the completed steps list
    expect(screen.getAllByText(/add your first target/i).length).toBeGreaterThan(0);

    // Advance to step 3
    fireEvent.click(screen.getByRole("button", { name: /^next/i }));
    expect(screen.getAllByText(/run a quick scan/i).length).toBeGreaterThan(0);
  });

  it("navigates to step N when a step indicator button is clicked", async () => {
    const { OnboardingWizard } = await import("@/components/onboarding-wizard");
    render(
      <WouterRouter base="">
        <OnboardingWizard />
      </WouterRouter>
    );
    fireEvent.click(screen.getByLabelText("Step 3"));
    expect(screen.getByText(/step 3 of 4/i)).toBeInTheDocument();
    expect(screen.getByText(/review your findings/i)).toBeInTheDocument();
  });

  it("navigates to the action route and calls dismiss when action button is clicked", async () => {
    const { OnboardingWizard } = await import("@/components/onboarding-wizard");
    const onDismiss = vi.fn();
    render(
      <WouterRouter base="">
        <OnboardingWizard onDismiss={onDismiss} />
      </WouterRouter>
    );
    // First step action is "Add Target" -> /targets
    const addTargetBtn = screen.getByRole("button", { name: /add target/i });
    fireEvent.click(addTargetBtn);
    expect(mockSetLocation).toHaveBeenCalledWith("/targets");
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });
});

describe("useOnboarding hook", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("returns show=true when wizard has not been dismissed before", async () => {
    const { useOnboarding } = await import("@/components/onboarding-wizard");
    // We test the hook via a simple component
    let hookResult: ReturnType<typeof useOnboarding> | null = null;
    function TestComponent() {
      hookResult = useOnboarding();
      return null;
    }
    render(<TestComponent />);
    expect(hookResult!.show).toBe(true);
  });

  it("returns show=false when wizard has been previously dismissed", async () => {
    localStorage.setItem("bfp_onboarding_dismissed", "true");
    const { useOnboarding } = await import("@/components/onboarding-wizard");
    let hookResult: ReturnType<typeof useOnboarding> | null = null;
    function TestComponent() {
      hookResult = useOnboarding();
      return null;
    }
    render(<TestComponent />);
    expect(hookResult!.show).toBe(false);
  });

  it("sets show=false and persists to localStorage when dismiss() is called", async () => {
    const { useOnboarding } = await import("@/components/onboarding-wizard");
    let hookResult: ReturnType<typeof useOnboarding> | null = null;
    function TestComponent() {
      hookResult = useOnboarding();
      return <button onClick={hookResult!.dismiss}>Dismiss</button>;
    }
    render(<TestComponent />);
    fireEvent.click(screen.getByRole("button", { name: /dismiss/i }));
    expect(hookResult!.show).toBe(false);
    expect(localStorage.getItem("bfp_onboarding_dismissed")).toBe("true");
  });
});
