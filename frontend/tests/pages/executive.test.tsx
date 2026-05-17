import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { vi, describe, it, expect, beforeEach, afterEach } from "vitest";
import "@testing-library/jest-dom";

vi.mock("wouter", () => ({
  useLocation: vi.fn(() => ["/executive", vi.fn()]),
  useParams: vi.fn(() => ({})),
  Link: ({ children, href }: { children: React.ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
  Route: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  Switch: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  Redirect: ({ to }: { to: string }) => <div data-testid="redirect" data-to={to} />,
  useRoute: vi.fn(() => [false, {}]),
}));

const mockExecMetrics = {
  mttd_hours: 4.2,
  mttr_days: 12,
  remediation_velocity: 8,
  vulnerability_density: 2.3,
  open_critical: 5,
  top_targets: [
    { url: "https://example.com", finding_count: 10, risk_score: 85 },
    { url: "https://api.example.com", finding_count: 6, risk_score: 70 },
  ],
  by_severity: [],
};

function setupFetchMock(anomalyOverride?: object) {
  vi.mocked(fetch).mockImplementation((input: RequestInfo | URL) => {
    const urlStr = input.toString();
    if (urlStr.includes("executive")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => mockExecMetrics,
      } as unknown as Response);
    }
    if (urlStr.includes("anomalies")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => anomalyOverride ?? { anomalies: [] },
      } as unknown as Response);
    }
    if (urlStr.includes("/api/scan-jobs")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => ({ items: [] }),
      } as unknown as Response);
    }
    return Promise.resolve({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({}),
    } as unknown as Response);
  });
}

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

describe("Executive Dashboard Page", () => {
  it("renders without crashing", async () => {
    setupFetchMock();
    const Executive = (await import("@/pages/executive")).default;
    expect(() => renderWithQuery(<Executive />)).not.toThrow();
  }, 15000);

  it("shows MTTD value after load", async () => {
    setupFetchMock();
    const Executive = (await import("@/pages/executive")).default;
    renderWithQuery(<Executive />);
    await waitFor(() => {
      expect(screen.getByText(/4\.2/)).toBeInTheDocument();
    });
  });

  it("shows MTTR value after load", async () => {
    setupFetchMock();
    const Executive = (await import("@/pages/executive")).default;
    renderWithQuery(<Executive />);
    await waitFor(() => {
      expect(screen.getByText(/12/)).toBeInTheDocument();
    });
  });

  it("renders heatmap section", async () => {
    setupFetchMock();
    const Executive = (await import("@/pages/executive")).default;
    renderWithQuery(<Executive />);
    await waitFor(() => {
      expect(
        screen.getByText(/heatmap|risk heatmap/i)
      ).toBeInTheDocument();
    });
  });

  it("shows anomaly banner when anomalies returned", async () => {
    const anomalyMsg = "Critical findings 275% above 30-day average";
    setupFetchMock({
      anomalies: [
        {
          metric: "critical_findings",
          current: 15,
          baseline: 4,
          spike_pct: 275,
          message: anomalyMsg,
        },
      ],
    });
    const Executive = (await import("@/pages/executive")).default;
    renderWithQuery(<Executive />);
    await waitFor(() => {
      expect(screen.getByText(anomalyMsg)).toBeInTheDocument();
    });
  });
});
