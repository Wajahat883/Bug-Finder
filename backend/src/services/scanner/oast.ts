/**
 * OAST (Out-of-Band Application Security Testing) integration.
 *
 * Connects to an interactsh server (https://github.com/projectdiscovery/interactsh).
 * When INTERACTSH_URL and INTERACTSH_TOKEN are set, every scanner that needs OOB
 * confirmation can call `allocateOastPayload()` to get a unique callback URL.
 * After the probe is sent, call `pollOastInteractions()` to check if the server
 * received a callback — confirming blind SQLi, blind SSRF, blind XSS, etc.
 */

export interface OastClient {
  /** Base domain registered with interactsh (e.g. abc123.oast.fun) */
  domain: string;
  /** Generate a unique sub-domain URL for one probe */
  allocate(tag: string): string;
  /** Poll interactions for a given tag — returns true if a callback was received */
  poll(tag: string, waitMs?: number): Promise<boolean>;
}

interface InteractshRegisterResponse {
  domain?: string;
  secret_key?: string;
}

interface InteractshPollResponse {
  data?: Array<{ full_id?: string }>;
}

export async function createOastClient(): Promise<OastClient | null> {
  const baseUrl = process.env["INTERACTSH_URL"];
  const token = process.env["INTERACTSH_TOKEN"] ?? "";

  if (!baseUrl) return null;

  // Register a new correlation session
  try {
    const reg = await fetch(`${baseUrl}/register`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ "secret-key": crypto.randomUUID(), correlationId: "bugfinder" }),
      signal: AbortSignal.timeout(8000),
    });

    if (!reg.ok) return null;
    const data = await reg.json() as InteractshRegisterResponse;
    const domain = data.domain;
    if (!domain) return null;

    return {
      domain,
      allocate(tag: string): string {
        // Each probe gets a unique subdomain: <tag-hash>.<domain>
        const safe = tag.replace(/[^a-z0-9]/gi, "").slice(0, 20).toLowerCase();
        return `https://${safe}.${domain}`;
      },
      async poll(tag: string, waitMs = 5000): Promise<boolean> {
        // Give the server time to receive the callback
        await new Promise(r => setTimeout(r, waitMs));
        const safe = tag.replace(/[^a-z0-9]/gi, "").slice(0, 20).toLowerCase();
        try {
          const res = await fetch(`${baseUrl}/poll?id=${encodeURIComponent(safe)}&secret=bugfinder`, {
            headers: token ? { Authorization: `Bearer ${token}` } : {},
            signal: AbortSignal.timeout(8000),
          });
          if (!res.ok) return false;
          const result = await res.json() as InteractshPollResponse;
          return Array.isArray(result.data) && result.data.length > 0;
        } catch {
          return false;
        }
      },
    };
  } catch {
    return null;
  }
}
