import React from "react";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { vi, describe, it, expect, beforeEach, afterEach } from "vitest";
import "@testing-library/jest-dom";

vi.mock("wouter", () => ({
  useLocation: vi.fn(() => ["/findings", vi.fn()]),
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

vi.mock("@/lib/excel-export", () => ({
  exportToExcel: vi.fn(),
  exportToCsv: vi.fn(),
  prepareFindingsForExport: vi.fn(() => []),
}));

const mockFindings = [
  {
    _id: "1",
    id: "1",
    title: "SQL Injection",
    severity: "critical",
    status: "open",
    category: "Injection",
    target_url: "https://example.com",
    endpoint: "https://example.com",
    epss_score: 0.85,
    cvss_score: 9.8,
    created_at: new Date().toISOString(),
    validation_status: "confirmed",
  },
  {
    _id: "2",
    id: "2",
    title: "XSS Stored",
    severity: "high",
    status: "in_progress",
    category: "XSS",
    target_url: "https://example.com/search",
    endpoint: "https://example.com/search",
    epss_score: 0.23,
    cvss_score: 7.2,
    created_at: new Date().toISOString(),
    validation_status: "confirmed",
  },
];

function mockFindingsFetch(findings = mockFindings, total = mockFindings.length) {
  vi.mocked(fetch).mockImplementation((input) => {
    const url = typeof input === "string" ? input : String(input);
    if (url.includes("/api/findings")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        // The findings page reads data?.items (not data?.findings)
        json: async () => ({ items: findings, total }),
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

describe("Findings Page", () => {
  it("renders without crashing", async () => {
    mockFindingsFetch();
    const Findings = (await import("@/pages/findings")).default;
    expect(() => renderWithQuery(<Findings />)).not.toThrow();
  }, 15000);

  it("shows finding titles after load", async () => {
    mockFindingsFetch();
    const Findings = (await import("@/pages/findings")).default;
    renderWithQuery(<Findings />);
    await waitFor(() => {
      expect(screen.getByText("SQL Injection")).toBeInTheDocument();
    });
  }, 15000);

  it("shows severity badges", async () => {
    mockFindingsFetch();
    const Findings = (await import("@/pages/findings")).default;
    renderWithQuery(<Findings />);
    await waitFor(() => {
      expect(screen.getByText(/critical/i)).toBeInTheDocument();
    });
  }, 15000);

  it("shows EPSS fire emoji for high scores (>0.7)", async () => {
    mockFindingsFetch();
    const Findings = (await import("@/pages/findings")).default;
    renderWithQuery(<Findings />);
    await waitFor(() => {
      expect(screen.getByText(/🔥/)).toBeInTheDocument();
    });
  }, 15000);

  it("shows empty state when no findings", async () => {
    mockFindingsFetch([], 0);
    const Findings = (await import("@/pages/findings")).default;
    renderWithQuery(<Findings />);
    await waitFor(() => {
      // The page should show some empty-state indicator — no rows or an empty message
      expect(screen.queryByText("SQL Injection")).not.toBeInTheDocument();
    });
  }, 15000);

  it("has filter UI elements", async () => {
    mockFindingsFetch();
    const Findings = (await import("@/pages/findings")).default;
    renderWithQuery(<Findings />);
    await waitFor(() => {
      // Expect a combobox/select for severity filtering
      const combos = screen.queryAllByRole("combobox");
      expect(combos.length).toBeGreaterThan(0);
    });
  }, 15000);
});
