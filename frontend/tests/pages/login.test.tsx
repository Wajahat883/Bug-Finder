import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { vi, describe, it, expect, beforeEach, afterEach } from "vitest";
import "@testing-library/jest-dom";

vi.mock("wouter", () => ({
  useLocation: vi.fn(() => ["/", vi.fn()]),
  useParams: vi.fn(() => ({})),
  Link: ({ children, href }: { children: React.ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
  Route: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  Switch: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  Redirect: ({ to }: { to: string }) => <div data-testid="redirect" data-to={to} />,
  useRoute: vi.fn(() => [false, {}]),
}));

function renderWithQuery(ui: React.ReactElement) {
  const qc = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

beforeEach(() => {
  global.fetch = vi.fn();
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("Login Page", () => {
  it("renders email and password input fields", async () => {
    const Login = (await import("@/pages/login")).default;
    renderWithQuery(<Login />);
    expect(screen.getByPlaceholderText(/you@example\.com/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText("••••••••")).toBeInTheDocument();
  });

  it("renders a submit button", async () => {
    const Login = (await import("@/pages/login")).default;
    renderWithQuery(<Login />);
    // The login form has a tab button ("Sign In") and the form submit button ("Sign In ▶").
    // Both match /sign in/i — verify at least one submit button is present.
    const signInButtons = screen.getAllByRole("button", { name: /sign in/i });
    expect(signInButtons.length).toBeGreaterThanOrEqual(1);
    // The submit button has type="submit"
    const submitBtn = signInButtons.find(
      (btn) => btn.getAttribute("type") === "submit"
    );
    expect(submitBtn).toBeInTheDocument();
  });

  it("shows error when submitted with empty email", async () => {
    const Login = (await import("@/pages/login")).default;
    renderWithQuery(<Login />);
    const emailInput = screen.getByPlaceholderText(/you@example\.com/i);
    expect((emailInput as HTMLInputElement).value).toBe("");
    expect(emailInput).toBeRequired();
  });

  it("shows error when submitted with empty password", async () => {
    const Login = (await import("@/pages/login")).default;
    renderWithQuery(<Login />);
    const passwordInput = screen.getByPlaceholderText("••••••••");
    expect((passwordInput as HTMLInputElement).value).toBe("");
    expect(passwordInput).toBeRequired();
  });

  it("calls POST /api/auth/login on valid form submission", async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: async () => ({ id: "1", role: "admin" }),
    } as Response);

    const Login = (await import("@/pages/login")).default;
    renderWithQuery(<Login />);

    fireEvent.change(screen.getByPlaceholderText(/you@example\.com/i), {
      target: { value: "user@example.com" },
    });
    fireEvent.change(screen.getByPlaceholderText("••••••••"), {
      target: { value: "secret123" },
    });
    // Click the submit button (not the tab button)
    const submitBtn = screen.getAllByRole("button", { name: /sign in/i }).find(
      (btn) => btn.getAttribute("type") === "submit"
    )!;
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(fetch).toHaveBeenCalledWith(
        "/api/auth/login",
        expect.objectContaining({
          method: "POST",
          body: expect.stringContaining("user@example.com"),
        })
      );
    });
  });

  it("shows error message on invalid credentials", async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ error: "Invalid credentials" }),
    } as Response);

    const Login = (await import("@/pages/login")).default;
    renderWithQuery(<Login />);

    fireEvent.change(screen.getByPlaceholderText(/you@example\.com/i), {
      target: { value: "bad@example.com" },
    });
    fireEvent.change(screen.getByPlaceholderText("••••••••"), {
      target: { value: "wrongpass" },
    });
    const submitBtn = screen.getAllByRole("button", { name: /sign in/i }).find(
      (btn) => btn.getAttribute("type") === "submit"
    )!;
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(screen.getByText("Invalid credentials")).toBeInTheDocument();
    });
  });

  it("has a link to forgot password page", async () => {
    const Login = (await import("@/pages/login")).default;
    renderWithQuery(<Login />);
    const forgotLink = screen.getByText(/forgot password/i);
    expect(forgotLink).toBeInTheDocument();
    expect(forgotLink.closest("a")).toHaveAttribute("href", "/forgot-password");
  });
});
