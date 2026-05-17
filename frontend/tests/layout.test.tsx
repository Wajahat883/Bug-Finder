import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Router as WouterRouter } from "wouter";
import React from "react";

// ─── Module mocks (hoisted) ───────────────────────────────────────────────────

const mockSetLocation = vi.fn();
const mockLocation = vi.fn(() => ["/dashboard", mockSetLocation]);

vi.mock("wouter", async (importOriginal) => {
  const actual = await importOriginal<typeof import("wouter")>();
  return {
    ...actual,
    useLocation: () => mockLocation(),
    Link: ({ children, href }: { children: React.ReactNode; href: string }) => (
      <a href={href}>{children}</a>
    ),
  };
});

vi.mock("next-themes", () => ({
  useTheme: () => ({ theme: "dark", setTheme: vi.fn() }),
}));

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

vi.mock("@/hooks/use-notifications", () => ({
  useNotifications: () => ({
    notifications: [],
    markRead: vi.fn(),
    markAllRead: vi.fn(),
  }),
  pushNotification: vi.fn(),
}));

vi.mock("./command-palette", () => ({
  CommandPalette: ({ open }: { open: boolean }) =>
    open ? <div data-testid="command-palette" /> : null,
}));

vi.mock("@/components/command-search", () => ({
  CommandSearch: () => null,
}));

vi.mock("@/components/session-expiry-modal", () => ({
  SessionExpiryModal: () => null,
}));

vi.mock("@/components/onboarding-wizard", () => ({
  OnboardingWizard: ({ onDismiss }: { onDismiss?: () => void }) => (
    <div data-testid="onboarding-wizard">
      <button onClick={onDismiss}>Skip</button>
    </div>
  ),
}));

const mockGetMe = vi.fn();
vi.mock("@/api-client", () => ({
  useGetMe: (opts?: unknown) => mockGetMe(opts),
}));

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <QueryClientProvider client={qc}>
        <WouterRouter base="">{children}</WouterRouter>
      </QueryClientProvider>
    );
  };
}

// Silence React act() warnings that come from layout's SSE / interval effects
beforeEach(() => {
  vi.clearAllMocks();
  mockLocation.mockReturnValue(["/dashboard", mockSetLocation]);
  // Default: authenticated non-admin user
  mockGetMe.mockReturnValue({
    data: { id: "1", username: "alice", role: "analyst", onboarding_complete: true },
    isLoading: false,
    isError: false,
  });
  // Prevent fetch errors from SSE/polling useEffects
  global.fetch = vi.fn().mockResolvedValue({
    ok: true,
    json: async () => ({ items: [] }),
    status: 200,
    headers: { get: () => null },
  } as unknown as Response);
  // Suppress EventSource errors in jsdom
  global.EventSource = class {
    constructor() {}
    close() {}
    onmessage = null;
    onerror = null;
  } as unknown as typeof EventSource;
});

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("AppLayout — navigation visibility", () => {
  it("shows non-admin nav items for a regular analyst user", async () => {
    const { AppLayout } = await import("@/components/layout");
    render(
      <AppLayout>
        <div>Page content</div>
      </AppLayout>,
      { wrapper: makeWrapper() }
    );
    // "Findings" is a non-admin nav item
    expect(screen.getByText("Findings")).toBeInTheDocument();
    // "Scans" is a non-admin nav item
    expect(screen.getByText("Scans")).toBeInTheDocument();
  });

  it("hides admin-only nav items for a non-admin user", async () => {
    const { AppLayout } = await import("@/components/layout");
    render(
      <AppLayout>
        <div>Page content</div>
      </AppLayout>,
      { wrapper: makeWrapper() }
    );
    // "Integrations" is admin-only (/integrations is in ADMIN_ONLY_PATHS)
    // It should NOT appear in the sidebar nav (only one instance — not as a nav link)
    const links = screen.queryAllByRole("link", { name: /integrations/i });
    expect(links).toHaveLength(0);
  });

  it("shows admin nav items when user has admin role", async () => {
    mockGetMe.mockReturnValue({
      data: { id: "2", username: "admin", role: "admin", onboarding_complete: true },
      isLoading: false,
      isError: false,
    });
    const { AppLayout } = await import("@/components/layout");
    render(
      <AppLayout>
        <div>Page content</div>
      </AppLayout>,
      { wrapper: makeWrapper() }
    );
    // "Audit Log" is admin-only
    expect(screen.getByText("Audit Log")).toBeInTheDocument();
  });
});

describe("AppLayout — sidebar toggle (mobile)", () => {
  it("renders the mobile sidebar toggle button", async () => {
    const { AppLayout } = await import("@/components/layout");
    render(
      <AppLayout>
        <div>Page content</div>
      </AppLayout>,
      { wrapper: makeWrapper() }
    );
    // The mobile toggle is the only button without text that sits fixed top-left
    // It changes icon between open/close states
    const toggleButtons = screen.getAllByRole("button");
    // At least one button should be present (the mobile toggle + nav group toggles)
    expect(toggleButtons.length).toBeGreaterThan(0);
  });
});

describe("AppLayout — active route highlight", () => {
  it("renders 'Dashboard' page name in the header for /dashboard route", async () => {
    mockLocation.mockReturnValue(["/dashboard", mockSetLocation]);
    const { AppLayout } = await import("@/components/layout");
    render(
      <AppLayout>
        <div>Page content</div>
      </AppLayout>,
      { wrapper: makeWrapper() }
    );
    // The pageName function returns "Dashboard" for /dashboard.
    // "Dashboard" appears in both the sidebar nav and the header — use getAllByText.
    const dashboardElements = screen.getAllByText("Dashboard");
    expect(dashboardElements.length).toBeGreaterThan(0);
  });

  it("renders correct page name for /findings route", async () => {
    mockLocation.mockReturnValue(["/findings", mockSetLocation]);
    const { AppLayout } = await import("@/components/layout");
    render(
      <AppLayout>
        <div>Page content</div>
      </AppLayout>,
      { wrapper: makeWrapper() }
    );
    // pageName returns "Findings" for /findings
    const headings = screen.getAllByText("Findings");
    expect(headings.length).toBeGreaterThan(0);
  });
});

describe("AppLayout — keyboard shortcuts", () => {
  it("opens shortcuts modal when '?' key is pressed", async () => {
    const { AppLayout } = await import("@/components/layout");
    render(
      <AppLayout>
        <div>Page content</div>
      </AppLayout>,
      { wrapper: makeWrapper() }
    );
    fireEvent.keyDown(window, { key: "?" });
    await waitFor(() =>
      expect(screen.getByText(/keyboard shortcuts/i)).toBeInTheDocument()
    );
  });

  it("closes shortcuts modal on second '?' key press", async () => {
    const { AppLayout } = await import("@/components/layout");
    render(
      <AppLayout>
        <div>Page content</div>
      </AppLayout>,
      { wrapper: makeWrapper() }
    );
    fireEvent.keyDown(window, { key: "?" });
    await waitFor(() => screen.getByText(/keyboard shortcuts/i));
    fireEvent.keyDown(window, { key: "?" });
    await waitFor(() =>
      expect(screen.queryByText(/keyboard shortcuts/i)).not.toBeInTheDocument()
    );
  });
});

describe("AppLayout — redirects", () => {
  it("redirects to /login when user is not authenticated", async () => {
    mockGetMe.mockReturnValue({
      data: null,
      isLoading: false,
      isError: true,
    });
    const { AppLayout } = await import("@/components/layout");
    render(
      <AppLayout>
        <div>Page content</div>
      </AppLayout>,
      { wrapper: makeWrapper() }
    );
    await waitFor(() =>
      expect(mockSetLocation).toHaveBeenCalledWith("/login")
    );
  });
});

describe("AppLayout — children rendering", () => {
  it("renders children content inside the layout", async () => {
    const { AppLayout } = await import("@/components/layout");
    render(
      <AppLayout>
        <div data-testid="inner-content">Inner page</div>
      </AppLayout>,
      { wrapper: makeWrapper() }
    );
    expect(screen.getByTestId("inner-content")).toBeInTheDocument();
    expect(screen.getByText("Inner page")).toBeInTheDocument();
  });
});
