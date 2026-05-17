import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { vi, describe, it, expect, beforeEach, afterEach } from "vitest";
import "@testing-library/jest-dom";

vi.mock("wouter", () => ({
  useLocation: vi.fn(() => ["/compliance", vi.fn()]),
  useParams: vi.fn(() => ({})),
  Link: ({ children, href }: { children: React.ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
  Route: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  Switch: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  Redirect: ({ to }: { to: string }) => <div data-testid="redirect" data-to={to} />,
  useRoute: vi.fn(() => [false, {}]),
}));

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

const mockReport = {
  score: 78,
  passing: 14,
  failing: 4,
  compliance_score_pct: 78,
  controls: [],
  soc2: { score: 78, controls: [] },
  iso27001: { score: 65, controls: [] },
  pci_dss: { score: 82, controls: [] },
  hipaa: { score: 70, controls: [] },
};

function setupFetch(overrides: Record<string, unknown> = {}) {
  vi.mocked(fetch).mockImplementation((input) => {
    const url = typeof input === "string" ? input : String(input);
    if (url.includes("/api/compliance/report")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => ({ ...mockReport, ...overrides }),
      } as unknown as Response);
    }
    if (url.includes("/api/compliance/history")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => [],
      } as unknown as Response);
    }
    if (url.includes("/api/compliance/attestations")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => [],
      } as unknown as Response);
    }
    if (url.includes("/api/findings")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => ({ findings: [], total: 0 }),
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
  setupFetch();
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("Compliance Dashboard Page", () => {
  it("renders without crashing", async () => {
    const ComplianceDashboard = (await import("@/pages/compliance-dashboard")).default;
    expect(() => renderWithQuery(<ComplianceDashboard />)).not.toThrow();
  }, 15000);

  it("renders SOC2 tab", async () => {
    const ComplianceDashboard = (await import("@/pages/compliance-dashboard")).default;
    renderWithQuery(<ComplianceDashboard />);
    await waitFor(() => {
      expect(screen.getByRole("button", { name: /soc\s*2/i })).toBeInTheDocument();
    });
  });

  it("renders ISO 27001 tab", async () => {
    const ComplianceDashboard = (await import("@/pages/compliance-dashboard")).default;
    renderWithQuery(<ComplianceDashboard />);
    await waitFor(() => {
      expect(screen.getByRole("button", { name: /iso\s*27001/i })).toBeInTheDocument();
    });
  });

  it("renders PCI-DSS tab", async () => {
    const ComplianceDashboard = (await import("@/pages/compliance-dashboard")).default;
    renderWithQuery(<ComplianceDashboard />);
    await waitFor(() => {
      expect(screen.getByRole("button", { name: /pci/i })).toBeInTheDocument();
    });
  });

  it("shows compliance score percentage", async () => {
    const ComplianceDashboard = (await import("@/pages/compliance-dashboard")).default;
    renderWithQuery(<ComplianceDashboard />);
    await waitFor(() => {
      // The circular score SVG renders "78%" text (may appear multiple times)
      const matches = screen.getAllByText(/78%/);
      expect(matches.length).toBeGreaterThan(0);
    });
  });

  it("clicking ISO tab fetches iso27001 data", async () => {
    const ComplianceDashboard = (await import("@/pages/compliance-dashboard")).default;
    renderWithQuery(<ComplianceDashboard />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /iso\s*27001/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: /iso\s*27001/i }));

    await waitFor(() => {
      const calls = vi.mocked(fetch).mock.calls.map((c) => c[0]?.toString() ?? "");
      expect(calls.some((url) => url.includes("iso27001"))).toBe(true);
    });
  });
});
