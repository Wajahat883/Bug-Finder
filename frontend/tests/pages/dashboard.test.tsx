import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { vi, describe, it, expect, beforeEach, afterEach } from "vitest";
import "@testing-library/jest-dom";

// Mock wouter
vi.mock("wouter", () => ({
  useLocation: vi.fn(() => ["/dashboard", vi.fn()]),
  useParams: vi.fn(() => ({})),
  Link: ({ children, href }: { children: React.ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
  Route: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  Switch: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

// Mock the onboarding wizard so it doesn't interfere
vi.mock("@/components/onboarding-wizard", () => ({
  OnboardingWizard: () => null,
  useOnboarding: () => ({ show: false, dismiss: vi.fn() }),
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

// Default mock data for dashboard
const mockStats = {
  total_scans: 42,
  active_scans: 2,
  critical_findings: 3,
  high_findings: 7,
  medium_findings: 12,
  low_findings: 5,
  info_findings: 1,
  total_findings: 28,
  risk_score: 75,
};

const mockActivity: never[] = [];
const mockScans = { items: [] };

function mockAllDashboardFetches() {
  vi.mocked(fetch).mockImplementation((input) => {
    const url = typeof input === "string" ? input : String(input);
    if (url.includes("/api/dashboard/stats")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        body: "not-null",
        text: async () => JSON.stringify(mockStats),
        json: async () => mockStats,
      } as unknown as Response);
    }
    if (url.includes("/api/dashboard/activity")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        body: "not-null",
        text: async () => JSON.stringify(mockActivity),
        json: async () => mockActivity,
      } as unknown as Response);
    }
    if (url.includes("/api/scan-jobs")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        body: "not-null",
        text: async () => JSON.stringify(mockScans),
        json: async () => mockScans,
      } as unknown as Response);
    }
    if (url.includes("/api/analytics/risk-trend") || url.includes("/api/risk-trend")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        body: "not-null",
        text: async () => JSON.stringify([]),
        json: async () => [],
      } as unknown as Response);
    }
    // Stream/SSE — return a rejected promise (EventSource is mocked separately)
    return Promise.reject(new Error("unhandled url: " + url));
  });
}

beforeEach(() => {
  global.fetch = vi.fn();
  // Minimal EventSource mock so SSE setup doesn't throw
  global.EventSource = vi.fn(() => ({
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    close: vi.fn(),
    onmessage: null,
    onerror: null,
    onopen: null,
    readyState: 0,
    url: "",
    withCredentials: false,
    CONNECTING: 0,
    OPEN: 1,
    CLOSED: 2,
    dispatchEvent: vi.fn(),
  })) as unknown as typeof EventSource;
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("Dashboard Page", () => {
  it("renders the page heading", async () => {
    mockAllDashboardFetches();
    const Dashboard = (await import("@/pages/dashboard")).default;
    renderWithQuery(<Dashboard />);
    await waitFor(() => {
      expect(
        screen.getByText(/security operations console/i)
      ).toBeInTheDocument();
    });
  });

  it("renders KPI stat cards after data loads", async () => {
    mockAllDashboardFetches();
    const Dashboard = (await import("@/pages/dashboard")).default;
    renderWithQuery(<Dashboard />);
    // totalScans = 42 should appear in a KPI card
    await waitFor(() => {
      expect(screen.getByText("42")).toBeInTheDocument();
    });
  });

  it("renders Total Scans label", async () => {
    mockAllDashboardFetches();
    const Dashboard = (await import("@/pages/dashboard")).default;
    renderWithQuery(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText(/total scans/i)).toBeInTheDocument();
    });
  });

  it("renders risk trend chart section", async () => {
    mockAllDashboardFetches();
    const Dashboard = (await import("@/pages/dashboard")).default;
    renderWithQuery(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText(/risk trend/i)).toBeInTheDocument();
    });
  });

  it("shows LIVE indicator when SSE connection fires open event", async () => {
    mockAllDashboardFetches();

    // Capture the EventSource instance so we can trigger events
    let capturedInstance: {
      onmessage: ((e: MessageEvent) => void) | null;
      onerror: (() => void) | null;
    } | null = null;

    global.EventSource = vi.fn(() => {
      const instance = {
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        close: vi.fn(),
        onmessage: null as ((e: MessageEvent) => void) | null,
        onerror: null as (() => void) | null,
        onopen: null,
        readyState: 0,
        url: "",
        withCredentials: false,
        CONNECTING: 0,
        OPEN: 1,
        CLOSED: 2,
        dispatchEvent: vi.fn(),
      };
      capturedInstance = instance;
      return instance;
    }) as unknown as typeof EventSource;

    const Dashboard = (await import("@/pages/dashboard")).default;
    renderWithQuery(<Dashboard />);

    // Trigger a stats_update SSE message to set isLive = true
    await waitFor(() => {
      expect(capturedInstance).not.toBeNull();
    });

    if (capturedInstance && capturedInstance.onmessage) {
      capturedInstance.onmessage(
        new MessageEvent("message", {
          data: JSON.stringify({ type: "stats_update", stats: mockStats }),
        })
      );
    }

    await waitFor(() => {
      expect(screen.getByText("LIVE")).toBeInTheDocument();
    });
  });

  it("renders NEW SCAN button", async () => {
    mockAllDashboardFetches();
    const Dashboard = (await import("@/pages/dashboard")).default;
    renderWithQuery(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByRole("button", { name: /new scan/i })).toBeInTheDocument();
    });
  });

  it("renders critical SLA warning strip when critical count > 0", async () => {
    mockAllDashboardFetches();
    const Dashboard = (await import("@/pages/dashboard")).default;
    renderWithQuery(<Dashboard />);
    await waitFor(() => {
      // 3 critical findings — should show the warning strip
      expect(screen.getByText(/critical finding/i)).toBeInTheDocument();
    });
  });
});
