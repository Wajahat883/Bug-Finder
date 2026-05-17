import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Switch, Route, Router as WouterRouter } from "wouter";
import React from "react";

function TestWrapper({ children, initialPath = "/" }: { children: React.ReactNode; initialPath?: string }) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WouterRouter base="">
          {children}
        </WouterRouter>
      </TooltipProvider>
    </QueryClientProvider>
  );
}

function renderWithRouter(ui: React.ReactElement) {
  return render(<TestWrapper>{ui}</TestWrapper>);
}

describe("Login page", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the login form", async () => {
    const Login = (await import("@/pages/login")).default;
    renderWithRouter(<Login />);
    // The login page uses placeholder "you@example.com" and "••••••••"
    expect(screen.getByPlaceholderText(/you@example\.com/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText("••••••••")).toBeInTheDocument();
    // Both the tab switcher and submit button say "Sign In" — verify at least one
    const signInBtns = screen.getAllByRole("button", { name: /sign in/i });
    expect(signInBtns.length).toBeGreaterThanOrEqual(1);
  });

  it("shows error on failed login attempt", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      json: async () => ({ error: "Invalid credentials" }),
    } as Response);
    const Login = (await import("@/pages/login")).default;
    renderWithRouter(<Login />);
    fireEvent.change(screen.getByPlaceholderText(/you@example\.com/i), {
      target: { value: "bad@example.com" },
    });
    fireEvent.change(screen.getByPlaceholderText("••••••••"), {
      target: { value: "wrongpass" },
    });
    // Click the submit (type="submit") button specifically
    const submitBtn = screen.getAllByRole("button", { name: /sign in/i }).find(
      (btn) => btn.getAttribute("type") === "submit"
    )!;
    fireEvent.click(submitBtn);
    await waitFor(() => {
      expect(screen.getByText(/invalid credentials/i)).toBeInTheDocument();
    });
  });
});

describe("Admin login page", () => {
  it("renders admin login with restricted warning", async () => {
    const AdminLogin = (await import("@/pages/admin-login")).default;
    renderWithRouter(<AdminLogin />);
    // Multiple elements may match — verify at least one is present
    expect(screen.getAllByText(/admin portal/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/restricted access/i).length).toBeGreaterThan(0);
    expect(screen.getByPlaceholderText(/admin email/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/admin password/i)).toBeInTheDocument();
  });
});

describe("404 Not Found page", () => {
  it("renders 404 message", async () => {
    const NotFound = (await import("@/pages/not-found")).default;
    renderWithRouter(<NotFound />);
    expect(screen.getByText(/404/i)).toBeInTheDocument();
  });
});

describe("CVSS Calculator", () => {
  it("renders calculator section", async () => {
    const CVSS = (await import("@/pages/cvss")).default;
    renderWithRouter(<CVSS />);
    // Multiple elements match these labels — verify at least one present
    expect(screen.getAllByText(/attack vector/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/scope/i).length).toBeGreaterThan(0);
  });
});

describe("Forgot password page", () => {
  it("renders email input and submit button", async () => {
    const ForgotPassword = (await import("@/pages/forgot-password")).default;
    renderWithRouter(<ForgotPassword />);
    // Placeholder is "you@example.com"; button text is "Send Reset Link"
    expect(screen.getByPlaceholderText(/you@example\.com/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /send reset link/i })).toBeInTheDocument();
  });
});

// Mock @/api-client at the top-level so Landing page can render
vi.mock("@/api-client", () => ({
  useGetMe: () => ({ data: null, isLoading: false }),
  useGetSettings: () => ({ data: {}, isLoading: false }),
  useGetDashboardStats: () => ({ data: undefined, isLoading: false }),
  useGetDashboardActivity: () => ({ data: undefined, isLoading: false }),
  useListScanJobs: () => ({ data: undefined, isLoading: false }),
}));

describe("Landing page", () => {
  it("renders hero section with CTA", async () => {
    const Landing = (await import("@/pages/landing")).default;
    renderWithRouter(<Landing />);
    expect(screen.getAllByText(/bug finder/i).length).toBeGreaterThan(0);
    // The landing page has "Start Free Scan" and "Sign In" buttons
    expect(
      screen.getAllByRole("button", { name: /start free scan/i }).length
    ).toBeGreaterThan(0);
    expect(
      screen.getAllByRole("button", { name: /sign in/i }).length
    ).toBeGreaterThan(0);
  });
});
