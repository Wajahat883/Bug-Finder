import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Router as WouterRouter } from "wouter";
import React from "react";

// Mock wouter's useLocation so navigation in the palette does not crash
const mockNav = vi.fn();
vi.mock("wouter", async (importOriginal) => {
  const actual = await importOriginal<typeof import("wouter")>();
  return {
    ...actual,
    useLocation: vi.fn(() => ["/dashboard", mockNav]),
  };
});

// Default: fetch returns empty results (no API data)
beforeEach(() => {
  vi.clearAllMocks();
  global.fetch = vi.fn().mockResolvedValue({
    ok: true,
    json: async () => ({ items: [] }),
  } as unknown as Response);
});

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

function renderPalette(open = true, onClose = vi.fn()) {
  return render(
    React.createElement(
      React.Suspense,
      { fallback: null },
      React.createElement(
        // Inline async load — we wrap below
        () => null
      )
    ),
    { wrapper: makeWrapper() }
  );
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("CommandPalette", () => {
  it("renders nothing when open=false", async () => {
    const { CommandPalette } = await import("@/components/command-palette");
    const onClose = vi.fn();
    render(<CommandPalette open={false} onClose={onClose} />, {
      wrapper: makeWrapper(),
    });
    expect(screen.queryByPlaceholderText(/search findings/i)).not.toBeInTheDocument();
  });

  it("renders search input when open=true", async () => {
    const { CommandPalette } = await import("@/components/command-palette");
    const onClose = vi.fn();
    render(<CommandPalette open={true} onClose={onClose} />, {
      wrapper: makeWrapper(),
    });
    expect(
      screen.getByPlaceholderText(/search findings, scans, targets, pages/i)
    ).toBeInTheDocument();
  });

  it("shows page results when query is empty (not a 'Type to search' hint)", async () => {
    const { CommandPalette } = await import("@/components/command-palette");
    render(<CommandPalette open={true} onClose={vi.fn()} />, {
      wrapper: makeWrapper(),
    });
    // When the query is empty, the component shows all pages (not the hint).
    // Verify at least one page result is visible.
    expect(screen.getByText("Dashboard")).toBeInTheDocument();
  });

  it("shows default page suggestions after typing a query that matches pages", async () => {
    const { CommandPalette } = await import("@/components/command-palette");
    render(<CommandPalette open={true} onClose={vi.fn()} />, {
      wrapper: makeWrapper(),
    });
    const input = screen.getByPlaceholderText(/search findings, scans, targets, pages/i);
    fireEvent.change(input, { target: { value: "dashboard" } });
    await waitFor(() =>
      expect(screen.getByText("Dashboard")).toBeInTheDocument()
    );
  });

  it("filters page results when the user types", async () => {
    const { CommandPalette } = await import("@/components/command-palette");
    render(<CommandPalette open={true} onClose={vi.fn()} />, {
      wrapper: makeWrapper(),
    });
    const input = screen.getByPlaceholderText(/search findings, scans, targets, pages/i);
    fireEvent.change(input, { target: { value: "cvss" } });
    await waitFor(() =>
      expect(screen.getByText("CVSS Calculator")).toBeInTheDocument()
    );
    // "Scans" is a page but should not appear when searching "cvss"
    expect(screen.queryByText(/^Scans$/)).not.toBeInTheDocument();
  });

  it("shows 'No results' message when query yields no matches", async () => {
    const { CommandPalette } = await import("@/components/command-palette");
    render(<CommandPalette open={true} onClose={vi.fn()} />, {
      wrapper: makeWrapper(),
    });
    const input = screen.getByPlaceholderText(/search findings, scans, targets, pages/i);
    fireEvent.change(input, { target: { value: "xyzzyzzz_no_match" } });
    await waitFor(() =>
      expect(
        screen.getByText(/no results for "xyzzyzzz_no_match"/i)
      ).toBeInTheDocument()
    );
  });

  it("closes when Escape key is pressed", async () => {
    const { CommandPalette } = await import("@/components/command-palette");
    const onClose = vi.fn();
    render(<CommandPalette open={true} onClose={onClose} />, {
      wrapper: makeWrapper(),
    });
    fireEvent.keyDown(window, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("closes when the X button is clicked", async () => {
    const { CommandPalette } = await import("@/components/command-palette");
    const onClose = vi.fn();
    render(<CommandPalette open={true} onClose={onClose} />, {
      wrapper: makeWrapper(),
    });
    // The X button is in the search bar header — it's the only button NOT inside the results list.
    // It has no text, so we find all buttons and pick the one in the input row (first button).
    const allButtons = screen.getAllByRole("button");
    // The X close button in the header is the first button rendered (before result rows).
    fireEvent.click(allButtons[0]);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("closes when the backdrop overlay is clicked", async () => {
    const { CommandPalette } = await import("@/components/command-palette");
    const onClose = vi.fn();
    const { container } = render(
      <CommandPalette open={true} onClose={onClose} />,
      { wrapper: makeWrapper() }
    );
    // The outer fixed backdrop div handles onClick -> onClose
    const backdrop = container.firstChild as HTMLElement;
    fireEvent.click(backdrop);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("navigates to the correct page and calls onClose when a result is clicked", async () => {
    const { CommandPalette } = await import("@/components/command-palette");
    const onClose = vi.fn();
    render(<CommandPalette open={true} onClose={onClose} />, {
      wrapper: makeWrapper(),
    });
    const input = screen.getByPlaceholderText(/search findings, scans, targets, pages/i);
    fireEvent.change(input, { target: { value: "compliance" } });
    await waitFor(() => screen.getByText("Compliance"));
    fireEvent.click(screen.getByText("Compliance"));
    expect(mockNav).toHaveBeenCalledWith("/compliance");
    expect(onClose).toHaveBeenCalled();
  });

  it("navigates via Enter key to the selected result", async () => {
    const { CommandPalette } = await import("@/components/command-palette");
    const onClose = vi.fn();
    render(<CommandPalette open={true} onClose={onClose} />, {
      wrapper: makeWrapper(),
    });
    const input = screen.getByPlaceholderText(/search findings, scans, targets, pages/i);
    fireEvent.change(input, { target: { value: "settings" } });
    await waitFor(() => screen.getByText("Settings"));
    // First result is selected by default (index 0), press Enter
    fireEvent.keyDown(window, { key: "Enter" });
    expect(mockNav).toHaveBeenCalledWith("/settings");
  });

  it("shows API-returned findings when search query length > 1", async () => {
    vi.mocked(fetch).mockImplementation((url) => {
      const urlStr = String(url);
      if (urlStr.includes("/api/findings")) {
        return Promise.resolve({
          ok: true,
          json: async () => ({
            items: [
              {
                id: "f1",
                title: "SQL Injection in login",
                endpoint: "/api/login",
                severity: "critical",
              },
            ],
          }),
        } as Response);
      }
      return Promise.resolve({
        ok: true,
        json: async () => ({ items: [] }),
      } as Response);
    });

    const { CommandPalette } = await import("@/components/command-palette");
    render(<CommandPalette open={true} onClose={vi.fn()} />, {
      wrapper: makeWrapper(),
    });
    const input = screen.getByPlaceholderText(/search findings, scans, targets, pages/i);
    fireEvent.change(input, { target: { value: "sql" } });
    await waitFor(() =>
      expect(screen.getByText("SQL Injection in login")).toBeInTheDocument()
    );
  });

  it("resets selection index to 0 when query changes", async () => {
    const { CommandPalette } = await import("@/components/command-palette");
    render(<CommandPalette open={true} onClose={vi.fn()} />, {
      wrapper: makeWrapper(),
    });
    const input = screen.getByPlaceholderText(/search findings, scans, targets, pages/i);
    // Set a query
    fireEvent.change(input, { target: { value: "scan" } });
    // Arrow down to move selection
    fireEvent.keyDown(window, { key: "ArrowDown" });
    // Change query — selection should reset
    fireEvent.change(input, { target: { value: "dashboard" } });
    await waitFor(() => screen.getByText("Dashboard"));
    // Press Enter — should navigate to first result (Dashboard)
    fireEvent.keyDown(window, { key: "Enter" });
    expect(mockNav).toHaveBeenCalledWith("/dashboard");
  });

  it("shows keyboard hint footer with ↑↓, ↵, and Esc keys", async () => {
    const { CommandPalette } = await import("@/components/command-palette");
    render(<CommandPalette open={true} onClose={vi.fn()} />, {
      wrapper: makeWrapper(),
    });
    expect(screen.getByText("navigate")).toBeInTheDocument();
    expect(screen.getByText("open")).toBeInTheDocument();
    expect(screen.getByText("close")).toBeInTheDocument();
  });
});
