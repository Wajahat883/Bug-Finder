/// <reference types="vite/client" />

const API_BASE = import.meta.env.VITE_API_URL?.replace(/\/+$/, "") ?? "";

if (API_BASE) {
  const originalFetch = window.fetch.bind(window);

  window.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
    if (
      typeof input === "string" &&
      (input.startsWith("/api/") || input.startsWith("/stream/"))
    ) {
      return originalFetch(API_BASE + input, init);
    }
    return originalFetch(input, init);
  }) as typeof fetch;

  const OriginalEventSource = window.EventSource;

  window.EventSource = class extends OriginalEventSource {
    constructor(url: string | URL, eventSourceInitDict?: EventSourceInit) {
      const urlStr = url instanceof URL ? url.toString() : url;
      if (urlStr.startsWith("/api/") || urlStr.startsWith("/stream/")) {
        super(API_BASE + urlStr, eventSourceInitDict);
      } else {
        super(url, eventSourceInitDict);
      }
    }

    static get CONNECTING() {
      return OriginalEventSource.CONNECTING;
    }
    static get OPEN() {
      return OriginalEventSource.OPEN;
    }
    static get CLOSED() {
      return OriginalEventSource.CLOSED;
    }
  } as unknown as typeof EventSource;
}
