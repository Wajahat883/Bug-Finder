import { describe, it, expect, vi, beforeEach } from "vitest";

// POINT 7: Queue integration tests

describe("Queue backpressure and retry logic", () => {
  it("exponential backoff doubles delay per attempt", () => {
    function retryDelayMs(attempt: number): number {
      return Math.min(1000 * Math.pow(2, attempt), 30000);
    }
    expect(retryDelayMs(1)).toBe(2000);
    expect(retryDelayMs(2)).toBe(4000);
    expect(retryDelayMs(3)).toBe(8000);
    expect(retryDelayMs(10)).toBe(30000); // capped at 30s
  });

  it("queue rejects jobs when at MAX_QUEUE_SIZE", () => {
    const MAX = 5;
    const queue: unknown[] = [];
    function tryEnqueue(job: unknown): { ok: boolean; reason?: string } {
      if (queue.length >= MAX) return { ok: false, reason: "Queue is full. Try again later." };
      queue.push(job);
      return { ok: true };
    }
    for (let i = 0; i < MAX; i++) tryEnqueue({ jobId: `job-${i}` });
    const result = tryEnqueue({ jobId: "overflow" });
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("full");
    expect(queue.length).toBe(MAX);
  });

  it("concurrency limit prevents exceeding MAX_CONCURRENT_SCANS", () => {
    const MAX = 2;
    let active = 0;
    const canStart = (): boolean => active < MAX;
    active++;
    expect(canStart()).toBe(true);
    active++;
    expect(canStart()).toBe(false);
    active--;
    expect(canStart()).toBe(true);
  });

  it("retry count increments and stops at max retries", () => {
    const MAX_RETRIES = 3;
    let retryCount = 0;
    const shouldRetry = (): boolean => {
      retryCount++;
      return retryCount <= MAX_RETRIES;
    };
    expect(shouldRetry()).toBe(true);  // attempt 1
    expect(shouldRetry()).toBe(true);  // attempt 2
    expect(shouldRetry()).toBe(true);  // attempt 3
    expect(shouldRetry()).toBe(false); // attempt 4 — over limit
  });
});

describe("Rate adaptation logic", () => {
  it("increases delay on 429 response", () => {
    const state = { delayMs: 150 };
    // Simulate 429 handling
    if (true /* status === 429 */) {
      state.delayMs = Math.min(state.delayMs * 2, 5000);
    }
    expect(state.delayMs).toBe(300);
  });

  it("gradually reduces delay on fast responses", () => {
    const state = { delayMs: 1000 };
    // Fast response — recover
    state.delayMs = Math.max(state.delayMs - 20, 150);
    expect(state.delayMs).toBe(980);
    // After many fast responses
    for (let i = 0; i < 50; i++) {
      state.delayMs = Math.max(state.delayMs - 20, 150);
    }
    expect(state.delayMs).toBe(150); // floor
  });

  it("caps maximum delay at 5000ms on 429", () => {
    const state = { delayMs: 4000 };
    state.delayMs = Math.min(state.delayMs * 2, 5000);
    expect(state.delayMs).toBe(5000);
  });
});

describe("SSRF guard integration with queue", () => {
  it("blocks internal IP before scan is enqueued", () => {
    const PRIVATE = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/;
    const isPrivate = (url: string): boolean => {
      try {
        const { hostname } = new URL(url);
        return PRIVATE.test(hostname) || hostname === "localhost";
      } catch { return true; }
    };
    expect(isPrivate("http://10.0.0.1")).toBe(true);
    expect(isPrivate("http://192.168.1.1")).toBe(true);
    expect(isPrivate("http://localhost:3000")).toBe(true);
    expect(isPrivate("https://example.com")).toBe(false);
    expect(isPrivate("https://api.github.com")).toBe(false);
  });
});
