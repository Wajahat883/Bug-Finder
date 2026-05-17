import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { vi, describe, it, expect, beforeEach, afterEach } from "vitest";
import "@testing-library/jest-dom";

vi.mock("wouter", () => ({
  useLocation: vi.fn(() => ["/settings", vi.fn()]),
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

// Mock the api-client hooks used by Settings
const mockSettingsData = {
  report_company_name: "Acme Corp",
  report_primary_color: "#6366f1",
  report_footer_text: "Confidential",
  ai_model: "claude-opus-4-5",
  default_export_format: "json",
  webhook_url: "",
  slack_webhook_url: "",
  teams_webhook_url: "",
  pagerduty_routing_key: "",
  notifications_enabled: true,
  ai_analysis_enabled: true,
  max_concurrent_scans: 3,
  smtp_host: "",
  smtp_port: 587,
  smtp_user: "",
  smtp_from: "noreply@bugfinder.io",
};

vi.mock("@/api-client", () => ({
  useGetSettings: () => ({
    data: mockSettingsData,
    isLoading: false,
    isError: false,
  }),
  useUpdateSettings: ({ mutation }: { mutation?: { onSuccess?: () => void; onError?: () => void } } = {}) => ({
    mutate: (args: unknown) => {
      if (mutation?.onSuccess) mutation.onSuccess();
    },
    isPending: false,
  }),
}));

function setupFetch() {
  vi.mocked(fetch).mockImplementation((input) => {
    const url = typeof input === "string" ? input : String(input);
    if (url.includes("/api/settings")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => mockSettingsData,
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
  // Prevent window.location.reload from throwing in jsdom
  Object.defineProperty(window, "location", {
    value: { ...window.location, reload: vi.fn() },
    writable: true,
  });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("Settings Page", () => {
  it("renders without crashing", async () => {
    const Settings = (await import("@/pages/settings")).default;
    expect(() => renderWithQuery(<Settings />)).not.toThrow();
  }, 15000);

  it("renders Report Branding section", async () => {
    const Settings = (await import("@/pages/settings")).default;
    renderWithQuery(<Settings />);
    await waitFor(() => {
      expect(screen.getByText(/report branding/i)).toBeInTheDocument();
    });
  }, 15000);

  it("renders company name input", async () => {
    const Settings = (await import("@/pages/settings")).default;
    renderWithQuery(<Settings />);
    await waitFor(() => {
      // The company name label is present in the Report Branding card
      expect(screen.getByText(/company name/i)).toBeInTheDocument();
    });
    // There should be a text input with the company name placeholder
    const inputs = screen.getAllByRole("textbox");
    expect(inputs.length).toBeGreaterThan(0);
  });

  it("renders restart tour button", async () => {
    const Settings = (await import("@/pages/settings")).default;
    renderWithQuery(<Settings />);
    await waitFor(() => {
      expect(screen.getByRole("button", { name: /restart tour/i })).toBeInTheDocument();
    });
  });

  it("save button calls PUT /api/settings", async () => {
    const Settings = (await import("@/pages/settings")).default;
    renderWithQuery(<Settings />);

    await waitFor(() => {
      expect(screen.getByText(/report branding/i)).toBeInTheDocument();
    });

    // Find the Save Branding button and click it — this triggers PUT /api/settings
    const saveButtons = screen.getAllByRole("button", { name: /save/i });
    // Click the branding save button (first Save button in the branding section)
    fireEvent.click(saveButtons[0]);

    await waitFor(() => {
      expect(fetch).toHaveBeenCalledWith(
        "/api/settings",
        expect.objectContaining({ method: "PUT" })
      );
    });
  });
});
