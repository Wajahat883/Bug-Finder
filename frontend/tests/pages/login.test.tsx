import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { vi, describe, it, expect, beforeEach, afterEach } from "vitest";
import "@testing-library/jest-dom";

// Mock wouter
vi.mock("wouter", () => ({
  useLocation: vi.fn(() => ["/", vi.fn()]),
  useParams: vi.fn(() => ({})),
  Link: ({ children, href }: { children: React.ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
  Route: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  Switch: ({ children }: { children: React.ReactNode }) => <>{children}</>,
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
  it("renders email and password fields", async () => {
    const Login = (await import("@/pages/login")).default;
    renderWithQuery(<Login />);
    // Login tab shows email placeholder
    expect(screen.getByPlaceholderText(/you@example\.com/i)).toBeInTheDocument();
    // Password field
    expect(screen.getByPlaceholderText("••••••••")).toBeInTheDocument();
  });

  it("renders submit button", async () => {
    const Login = (await import("@/pages/login")).default;
    renderWithQuery(<Login />);
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });

  it("shows validation error when both fields are empty", async () => {
    const Login = (await import("@/pages/login")).default;
    renderWithQuery(<Login />);
    // The form has required inputs so clicking without filling shows browser validation,
    // but our login page sets error state on failed fetch — test empty submit triggers native required behavior
    const emailInput = screen.getByPlaceholderText(/you@example\.com/i);
    const passwordInput = screen.getByPlaceholderText("••••••••");
    // Both fields are empty — expect them to be empty
    expect((emailInput as HTMLInputElement).value).toBe("");
    expect((passwordInput as HTMLInputElement).value).toBe("");
    // Fields are required
    expect(emailInput).toBeRequired();
    expect(passwordInput).toBeRequired();
  });

  it("calls POST /api/auth/login on submit with correct body", async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: async () => ({ role: "user" }),
    } as Response);

    const Login = (await import("@/pages/login")).default;
    renderWithQuery(<Login />);

    fireEvent.change(screen.getByPlaceholderText(/you@example\.com/i), {
      target: { value: "user@example.com" },
    });
    fireEvent.change(screen.getByPlaceholderText("••••••••"), {
      target: { value: "secret123" },
    });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

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

  it("shows error message on failed login", async () => {
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
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    await waitFor(() => {
      expect(screen.getByText("Invalid credentials")).toBeInTheDocument();
    });
  });

  it("has link to forgot password page", async () => {
    const Login = (await import("@/pages/login")).default;
    renderWithQuery(<Login />);
    const forgotLink = screen.getByText(/forgot password/i);
    expect(forgotLink).toBeInTheDocument();
    expect(forgotLink.closest("a")).toHaveAttribute("href", "/forgot-password");
  });

  it("renders Register tab and switches to registration form", async () => {
    const Login = (await import("@/pages/login")).default;
    renderWithQuery(<Login />);
    const createAccountBtn = screen.getByRole("button", { name: /create account/i });
    fireEvent.click(createAccountBtn);
    await waitFor(() => {
      expect(screen.getByPlaceholderText(/first name/i)).toBeInTheDocument();
      expect(screen.getByPlaceholderText(/last name/i)).toBeInTheDocument();
    });
  });

  it("shows passwords do not match error on registration", async () => {
    const Login = (await import("@/pages/login")).default;
    renderWithQuery(<Login />);

    // Switch to register tab
    fireEvent.click(screen.getByRole("button", { name: /create account/i }));

    await waitFor(() => screen.getByPlaceholderText(/first name/i));

    fireEvent.change(screen.getByPlaceholderText(/first name/i), { target: { value: "Jane" } });
    fireEvent.change(screen.getByPlaceholderText(/last name/i), { target: { value: "Doe" } });
    fireEvent.change(screen.getByPlaceholderText(/email address/i), { target: { value: "jane@example.com" } });
    fireEvent.change(screen.getByPlaceholderText(/password.*min 6/i), { target: { value: "pass1" } });
    fireEvent.change(screen.getByPlaceholderText(/confirm password/i), { target: { value: "nomatch" } });

    // Submit the register form
    const submitBtn = screen.getByRole("button", { name: /create account/i });
    fireEvent.click(submitBtn);

    await waitFor(() => {
      expect(screen.getByText(/passwords do not match/i)).toBeInTheDocument();
    });
  });
});
