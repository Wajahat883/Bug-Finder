import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import React from "react";

// Helper: a component that throws when shouldThrow is true
function ThrowError({ shouldThrow }: { shouldThrow: boolean }) {
  if (shouldThrow) throw new Error("Test error message");
  return <div>Safe content</div>;
}

// Suppress React's error boundary console.error noise in tests
let consoleErrorSpy: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
  consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => {
  consoleErrorSpy.mockRestore();
});

describe("ErrorBoundary", () => {
  it("renders children when there is no error", async () => {
    const { ErrorBoundary } = await import("@/components/error-boundary");
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={false} />
      </ErrorBoundary>
    );
    expect(screen.getByText("Safe content")).toBeInTheDocument();
  });

  it("catches errors and shows default fallback UI", async () => {
    const { ErrorBoundary } = await import("@/components/error-boundary");
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );
    expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
    expect(screen.queryByText("Safe content")).not.toBeInTheDocument();
  });

  it("displays the error message in the fallback UI", async () => {
    const { ErrorBoundary } = await import("@/components/error-boundary");
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );
    expect(screen.getByText(/test error message/i)).toBeInTheDocument();
  });

  it("shows 'Try Again' and 'Reload Page' buttons in fallback UI", async () => {
    const { ErrorBoundary } = await import("@/components/error-boundary");
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );
    expect(screen.getByRole("button", { name: /try again/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /reload page/i })).toBeInTheDocument();
  });

  it("resets the boundary and shows children again when 'Try Again' is clicked", async () => {
    const { ErrorBoundary } = await import("@/components/error-boundary");

    // Use a stateful wrapper so we can control whether the child throws
    function ResettableWrapper() {
      const [shouldThrow, setShouldThrow] = React.useState(true);
      return (
        <ErrorBoundary
          onReset={() => setShouldThrow(false)}
        >
          <ThrowError shouldThrow={shouldThrow} />
        </ErrorBoundary>
      );
    }

    render(<ResettableWrapper />);
    expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /try again/i }));

    expect(screen.getByText("Safe content")).toBeInTheDocument();
    expect(screen.queryByText(/something went wrong/i)).not.toBeInTheDocument();
  });

  it("calls onReset callback when 'Try Again' is clicked", async () => {
    const { ErrorBoundary } = await import("@/components/error-boundary");
    const onReset = vi.fn();
    render(
      <ErrorBoundary onReset={onReset}>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );
    fireEvent.click(screen.getByRole("button", { name: /try again/i }));
    expect(onReset).toHaveBeenCalledTimes(1);
  });

  it("renders a custom fallback when the fallback prop is provided", async () => {
    const { ErrorBoundary } = await import("@/components/error-boundary");
    render(
      <ErrorBoundary fallback={<div>Custom error UI</div>}>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );
    expect(screen.getByText("Custom error UI")).toBeInTheDocument();
    expect(screen.queryByText(/something went wrong/i)).not.toBeInTheDocument();
  });

  it("does not render the fallback when children do not throw", async () => {
    const { ErrorBoundary } = await import("@/components/error-boundary");
    render(
      <ErrorBoundary fallback={<div>Custom error UI</div>}>
        <ThrowError shouldThrow={false} />
      </ErrorBoundary>
    );
    expect(screen.queryByText("Custom error UI")).not.toBeInTheDocument();
    expect(screen.getByText("Safe content")).toBeInTheDocument();
  });

  it("calls window.location.reload when 'Reload Page' is clicked", async () => {
    const { ErrorBoundary } = await import("@/components/error-boundary");
    const reloadSpy = vi.fn();
    Object.defineProperty(window, "location", {
      configurable: true,
      value: { ...window.location, reload: reloadSpy },
    });

    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );
    fireEvent.click(screen.getByRole("button", { name: /reload page/i }));
    expect(reloadSpy).toHaveBeenCalledTimes(1);
  });
});
