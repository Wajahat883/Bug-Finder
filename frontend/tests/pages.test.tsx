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
    expect(screen.getByPlaceholderText(/email/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/password/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });

  it("shows error on empty submit", async () => {
    const Login = (await import("@/pages/login")).default;
    renderWithRouter(<Login />);
    const btn = screen.getByRole("button", { name: /sign in/i });
    fireEvent.click(btn);
    await waitFor(() => {
      expect(screen.getByText(/email and password are required/i)).toBeInTheDocument();
    });
  });
});

describe("Admin login page", () => {
  it("renders admin login with restricted warning", async () => {
    const AdminLogin = (await import("@/pages/admin-login")).default;
    renderWithRouter(<AdminLogin />);
    expect(screen.getByText(/admin portal/i)).toBeInTheDocument();
    expect(screen.getByText(/restricted access/i)).toBeInTheDocument();
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
    expect(screen.getByText(/attack vector/i)).toBeInTheDocument();
    expect(screen.getByText(/scope/i)).toBeInTheDocument();
  });
});

describe("Forgot password page", () => {
  it("renders email input and submit button", async () => {
    const ForgotPassword = (await import("@/pages/forgot-password")).default;
    renderWithRouter(<ForgotPassword />);
    expect(screen.getByPlaceholderText(/email/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /send/i })).toBeInTheDocument();
  });
});

describe("Landing page", () => {
  it("renders hero section with CTA", async () => {
    vi.mock("@/api-client", () => ({
      useGetMe: () => ({ data: null, isLoading: false }),
      useGetSettings: () => ({ data: {}, isLoading: false }),
    }));

    const Landing = (await import("@/pages/landing")).default;
    renderWithRouter(<Landing />);
    expect(screen.getByText(/bug finder/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /start free scan/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });
});
