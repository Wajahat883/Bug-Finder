import React from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { vi, describe, it, expect, beforeEach, afterEach } from "vitest";
import "@testing-library/jest-dom";

vi.mock("wouter", () => ({
  useLocation: vi.fn(() => ["/admin/policy", vi.fn()]),
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

const mockPolicy = {
  enforce_2fa: false,
  session_timeout_minutes: 60,
  data_retention_days: 365,
  max_failed_logins: 5,
  password_min_length: 12,
  require_mfa_roles: [],
  mfa_grace_days: 7,
  max_failed_login_attempts: 5,
  lockout_duration_minutes: 15,
  scan_retention_days: 365,
  finding_retention_days: 730,
  audit_log_retention_days: 1095,
  notification_retention_days: 30,
};

function setupFetch() {
  vi.mocked(fetch).mockImplementation((input) => {
    const url = typeof input === "string" ? input : String(input);
    if (url.includes("/api/admin/policy")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => mockPolicy,
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

describe("Admin Policy Page", () => {
  it("renders without crashing for admin user", async () => {
    const AdminPolicy = (await import("@/pages/admin-policy")).default;
    expect(() => renderWithQuery(<AdminPolicy />)).not.toThrow();
  }, 15000);

  it("renders MFA enforcement section", async () => {
    const AdminPolicy = (await import("@/pages/admin-policy")).default;
    renderWithQuery(<AdminPolicy />);
    await waitFor(() => {
      const matches = screen.getAllByText(/mfa|two.factor|multi.factor|two-factor|2fa/i);
      expect(matches.length).toBeGreaterThan(0);
    });
  });

  it("renders session timeout input", async () => {
    const AdminPolicy = (await import("@/pages/admin-policy")).default;
    renderWithQuery(<AdminPolicy />);
    await waitFor(() => {
      // The session timeout is rendered as a number input
      const numberInputs = screen.getAllByRole("spinbutton");
      expect(numberInputs.length).toBeGreaterThan(0);
    });
  });

  it("save button calls PUT /api/admin/policy", async () => {
    const AdminPolicy = (await import("@/pages/admin-policy")).default;
    renderWithQuery(<AdminPolicy />);

    await waitFor(() => {
      const saveButtons = screen.getAllByRole("button", { name: /save/i });
      expect(saveButtons.length).toBeGreaterThan(0);
    });

    const saveButtons = screen.getAllByRole("button", { name: /save/i });
    fireEvent.click(saveButtons[0]);

    await waitFor(() => {
      const calls = vi.mocked(fetch).mock.calls;
      // The page uses PUT for most policy mutations and PATCH for the main policy form
      const mutationCall = calls.find(
        (c) =>
          c[0]?.toString().includes("/api/admin/policy") &&
          ["PUT", "PATCH"].includes((c[1] as RequestInit)?.method ?? "")
      );
      expect(mutationCall).toBeDefined();
    });
  });
});
