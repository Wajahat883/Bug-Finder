import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";

// Mock fetch globally
global.fetch = vi.fn();

function makeWrapper() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
  };
}

const MOCK_NOTIFICATIONS = [
  {
    id: "1",
    type: "critical",
    title: "SQL Injection Found",
    message: "Critical SQL injection vulnerability detected on /api/users",
    read: false,
    created_at: new Date().toISOString(),
  },
  {
    id: "2",
    type: "scan",
    title: "Scan Complete",
    message: "Full scan of example.com finished with 3 findings",
    read: true,
    created_at: new Date().toISOString(),
  },
];

describe("NotificationBell", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: async () => MOCK_NOTIFICATIONS,
    } as Response);
  });

  it("renders bell icon with accessible label", async () => {
    const { NotificationBell } = await import("@/components/notification-bell");
    render(<NotificationBell />, { wrapper: makeWrapper() });
    expect(screen.getByLabelText(/notifications/i)).toBeInTheDocument();
  });

  it("shows unread count badge when there are unread notifications", async () => {
    const { NotificationBell } = await import("@/components/notification-bell");
    render(<NotificationBell />, { wrapper: makeWrapper() });
    // 1 unread (id: "1", read: false)
    await waitFor(() => expect(screen.getByText("1")).toBeInTheDocument());
  });

  it("does not show badge when all notifications are read", async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: async () => [{ ...MOCK_NOTIFICATIONS[0], read: true }, MOCK_NOTIFICATIONS[1]],
    } as Response);
    const { NotificationBell } = await import("@/components/notification-bell");
    render(<NotificationBell />, { wrapper: makeWrapper() });
    await waitFor(() => {
      // badge should not be present
      expect(screen.queryByText("2")).not.toBeInTheDocument();
    });
  });

  it("opens dropdown panel when bell is clicked", async () => {
    const { NotificationBell } = await import("@/components/notification-bell");
    render(<NotificationBell />, { wrapper: makeWrapper() });
    fireEvent.click(screen.getByLabelText(/notifications/i));
    await waitFor(() =>
      expect(screen.getByText("SQL Injection Found")).toBeInTheDocument()
    );
  });

  it("shows notification messages inside dropdown", async () => {
    const { NotificationBell } = await import("@/components/notification-bell");
    render(<NotificationBell />, { wrapper: makeWrapper() });
    fireEvent.click(screen.getByLabelText(/notifications/i));
    await waitFor(() => {
      expect(screen.getByText("SQL Injection Found")).toBeInTheDocument();
      expect(screen.getByText("Scan Complete")).toBeInTheDocument();
    });
  });

  it("shows 'All caught up!' when there are no notifications", async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: async () => [],
    } as Response);
    const { NotificationBell } = await import("@/components/notification-bell");
    render(<NotificationBell />, { wrapper: makeWrapper() });
    fireEvent.click(screen.getByLabelText(/notifications/i));
    await waitFor(() =>
      expect(screen.getByText(/all caught up/i)).toBeInTheDocument()
    );
  });

  it("calls mark-all-read endpoint when 'Mark all read' button is clicked", async () => {
    const { NotificationBell } = await import("@/components/notification-bell");
    render(<NotificationBell />, { wrapper: makeWrapper() });
    fireEvent.click(screen.getByLabelText(/notifications/i));
    await waitFor(() => screen.getByText(/mark all read/i));

    // Reset mock so we can assert the new call
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: async () => ({ success: true }),
    } as Response);

    fireEvent.click(screen.getByText(/mark all read/i));

    await waitFor(() =>
      expect(fetch).toHaveBeenCalledWith(
        expect.stringContaining("read-all"),
        expect.objectContaining({ method: "POST" })
      )
    );
  });

  it("closes dropdown when X button is clicked", async () => {
    const { NotificationBell } = await import("@/components/notification-bell");
    render(<NotificationBell />, { wrapper: makeWrapper() });
    fireEvent.click(screen.getByLabelText(/notifications/i));
    await waitFor(() => screen.getByText("SQL Injection Found"));

    // The X button inside the dropdown header closes it
    const closeButtons = screen.getAllByRole("button");
    // Find the button that contains the X icon (it has no text label, but is after the mark-all-read button)
    const xButton = closeButtons.find(
      (btn) => !btn.getAttribute("aria-label") && btn !== screen.getByLabelText(/notifications/i)
        && !btn.textContent?.toLowerCase().includes("mark")
    );
    expect(xButton).toBeDefined();
    fireEvent.click(xButton!);
    expect(screen.queryByText("SQL Injection Found")).not.toBeInTheDocument();
  });

  it("marks single notification as read when clicked", async () => {
    vi.mocked(fetch)
      .mockResolvedValueOnce({ ok: true, json: async () => MOCK_NOTIFICATIONS } as Response)
      .mockResolvedValue({ ok: true, json: async () => ({ success: true }) } as Response);

    const { NotificationBell } = await import("@/components/notification-bell");
    render(<NotificationBell />, { wrapper: makeWrapper() });
    fireEvent.click(screen.getByLabelText(/notifications/i));
    await waitFor(() => screen.getByText("SQL Injection Found"));

    fireEvent.click(screen.getByText("SQL Injection Found"));

    await waitFor(() =>
      expect(fetch).toHaveBeenCalledWith(
        expect.stringContaining("/api/notifications/1/read"),
        expect.objectContaining({ method: "PATCH" })
      )
    );
  });

  it("shows unread count capped at 9+ when more than 9 unread notifications exist", async () => {
    const manyUnread = Array.from({ length: 12 }, (_, i) => ({
      id: String(i),
      type: "scan",
      title: `Notification ${i}`,
      message: "message",
      read: false,
      created_at: new Date().toISOString(),
    }));
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: async () => manyUnread,
    } as Response);

    const { NotificationBell } = await import("@/components/notification-bell");
    render(<NotificationBell />, { wrapper: makeWrapper() });
    await waitFor(() => expect(screen.getByText("9+")).toBeInTheDocument());
  });

  it("shows 'View all notifications' link when notifications exist", async () => {
    const { NotificationBell } = await import("@/components/notification-bell");
    render(<NotificationBell />, { wrapper: makeWrapper() });
    fireEvent.click(screen.getByLabelText(/notifications/i));
    await waitFor(() =>
      expect(screen.getByText(/view all notifications/i)).toBeInTheDocument()
    );
  });
});
