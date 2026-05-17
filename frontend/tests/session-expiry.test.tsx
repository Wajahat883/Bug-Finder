import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { Router as WouterRouter } from "wouter";
import React from "react";

// Mock wouter's useLocation
const mockNav = vi.fn();
vi.mock("wouter", async (importOriginal) => {
  const actual = await importOriginal<typeof import("wouter")>();
  return {
    ...actual,
    useLocation: vi.fn(() => ["/dashboard", mockNav]),
  };
});

// Mock use-toast
vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

// ─── Helpers ──────────────────────────────────────────────────────────────────

function renderModal() {
  return render(
    <WouterRouter base="">
      {React.createElement(
        React.Fragment,
        null,
        React.createElement(
          (async () => {
            const { SessionExpiryModal } = await import("@/components/session-expiry-modal");
            return SessionExpiryModal;
          })() as unknown as React.ComponentType,
          null
        )
      )}
    </WouterRouter>
  );
}

// A simpler inline helper that imports synchronously per test
async function renderSessionModal() {
  // Reset interceptor state between tests by clearing the module cache flag
  // We reimport the module to get a fresh component
  const { SessionExpiryModal, SESSION_EXPIRED_EVENT } = await import(
    "@/components/session-expiry-modal"
  );
  const utils = render(
    <WouterRouter base="">
      <SessionExpiryModal />
    </WouterRouter>
  );
  return { ...utils, SESSION_EXPIRED_EVENT };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

beforeEach(() => {
  vi.clearAllMocks();
  global.fetch = vi.fn();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("SessionExpiryModal", () => {
  it("does not render the modal by default (before any session:expired event)", async () => {
    const { SessionExpiryModal } = await import("@/components/session-expiry-modal");
    render(
      <WouterRouter base="">
        <SessionExpiryModal />
      </WouterRouter>
    );
    expect(screen.queryByText(/session expired/i)).not.toBeInTheDocument();
  });

  it("shows modal when SESSION_EXPIRED_EVENT is dispatched", async () => {
    const { SessionExpiryModal, SESSION_EXPIRED_EVENT } = await import(
      "@/components/session-expiry-modal"
    );
    render(
      <WouterRouter base="">
        <SessionExpiryModal />
      </WouterRouter>
    );
    window.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT));
    await waitFor(() =>
      expect(screen.getByText(/session expired/i)).toBeInTheDocument()
    );
  });

  it("shows email and password inputs when modal is open", async () => {
    const { SessionExpiryModal, SESSION_EXPIRED_EVENT } = await import(
      "@/components/session-expiry-modal"
    );
    render(
      <WouterRouter base="">
        <SessionExpiryModal />
      </WouterRouter>
    );
    window.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT));
    await waitFor(() => screen.getByText(/session expired/i));
    expect(screen.getByPlaceholderText(/your@email\.com/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/••••••/)).toBeInTheDocument();
  });

  it("shows error when 'Sign In' is clicked with empty credentials", async () => {
    const { SessionExpiryModal, SESSION_EXPIRED_EVENT } = await import(
      "@/components/session-expiry-modal"
    );
    render(
      <WouterRouter base="">
        <SessionExpiryModal />
      </WouterRouter>
    );
    window.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT));
    await waitFor(() => screen.getByText(/session expired/i));

    fireEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    await waitFor(() =>
      expect(
        screen.getByText(/email and password are required/i)
      ).toBeInTheDocument()
    );
  });

  it("calls /api/auth/login with credentials when 'Sign In' is clicked", async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: async () => ({ success: true }),
    } as Response);

    const { SessionExpiryModal, SESSION_EXPIRED_EVENT } = await import(
      "@/components/session-expiry-modal"
    );
    render(
      <WouterRouter base="">
        <SessionExpiryModal />
      </WouterRouter>
    );
    window.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT));
    await waitFor(() => screen.getByText(/session expired/i));

    fireEvent.change(screen.getByPlaceholderText(/your@email\.com/i), {
      target: { value: "user@example.com" },
    });
    fireEvent.change(screen.getByPlaceholderText(/••••••/), {
      target: { value: "password123" },
    });
    fireEvent.click(screen.getByRole("button", { name: /^sign in$/i }));

    await waitFor(() =>
      expect(fetch).toHaveBeenCalledWith(
        "/api/auth/login",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ email: "user@example.com", password: "password123" }),
        })
      )
    );
  });

  it("closes modal after a successful re-login", async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: async () => ({ success: true }),
    } as Response);

    const { SessionExpiryModal, SESSION_EXPIRED_EVENT } = await import(
      "@/components/session-expiry-modal"
    );
    render(
      <WouterRouter base="">
        <SessionExpiryModal />
      </WouterRouter>
    );
    window.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT));
    await waitFor(() => screen.getByText(/session expired/i));

    fireEvent.change(screen.getByPlaceholderText(/your@email\.com/i), {
      target: { value: "user@example.com" },
    });
    fireEvent.change(screen.getByPlaceholderText(/••••••/), {
      target: { value: "correctpassword" },
    });
    fireEvent.click(screen.getByRole("button", { name: /^sign in$/i }));

    await waitFor(() =>
      expect(screen.queryByText(/session expired/i)).not.toBeInTheDocument()
    );
  });

  it("shows error message when login attempt fails with bad credentials", async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: false,
      json: async () => ({ error: "Invalid credentials" }),
    } as Response);

    const { SessionExpiryModal, SESSION_EXPIRED_EVENT } = await import(
      "@/components/session-expiry-modal"
    );
    render(
      <WouterRouter base="">
        <SessionExpiryModal />
      </WouterRouter>
    );
    window.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT));
    await waitFor(() => screen.getByText(/session expired/i));

    fireEvent.change(screen.getByPlaceholderText(/your@email\.com/i), {
      target: { value: "user@example.com" },
    });
    fireEvent.change(screen.getByPlaceholderText(/••••••/), {
      target: { value: "wrongpassword" },
    });
    fireEvent.click(screen.getByRole("button", { name: /^sign in$/i }));

    await waitFor(() =>
      expect(screen.getByText(/invalid credentials/i)).toBeInTheDocument()
    );
  });

  it("navigates to /login when 'Go to Login' button is clicked", async () => {
    const { SessionExpiryModal, SESSION_EXPIRED_EVENT } = await import(
      "@/components/session-expiry-modal"
    );
    render(
      <WouterRouter base="">
        <SessionExpiryModal />
      </WouterRouter>
    );
    window.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT));
    await waitFor(() => screen.getByText(/session expired/i));

    fireEvent.click(screen.getByRole("button", { name: /go to login/i }));
    expect(mockNav).toHaveBeenCalledWith("/login");
  });

  it("fires SESSION_EXPIRED_EVENT when fetch returns 401 on non-auth routes", async () => {
    // Re-import to trigger installSessionInterceptor fresh
    const { installSessionInterceptor, SESSION_EXPIRED_EVENT } = await import(
      "@/components/session-expiry-modal"
    );

    const eventSpy = vi.fn();
    window.addEventListener(SESSION_EXPIRED_EVENT, eventSpy);

    // Install the interceptor
    installSessionInterceptor();

    // Simulate a 401 response on a non-auth route
    const originalFetch = global.fetch as ReturnType<typeof vi.fn>;
    originalFetch.mockResolvedValue({
      status: 401,
      ok: false,
      json: async () => ({}),
      url: "/api/findings",
    } as unknown as Response);

    await window.fetch("/api/findings");

    await waitFor(() => expect(eventSpy).toHaveBeenCalledTimes(1));
    window.removeEventListener(SESSION_EXPIRED_EVENT, eventSpy);
  });
});
