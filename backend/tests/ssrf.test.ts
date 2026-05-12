import { describe, it, expect } from "vitest";
import { checkSsrf } from "../src/lib/ssrf-guard";

describe("SSRF Guard", () => {
  it("allows public HTTPS URLs", () => {
    expect(checkSsrf("https://example.com").allowed).toBe(true);
    expect(checkSsrf("https://google.com/login").allowed).toBe(true);
    expect(checkSsrf("http://testphp.vulnweb.com").allowed).toBe(true);
  });

  it("blocks localhost", () => {
    expect(checkSsrf("http://localhost").allowed).toBe(false);
    expect(checkSsrf("http://localhost:8080/admin").allowed).toBe(false);
  });

  it("blocks 127.x.x.x", () => {
    expect(checkSsrf("http://127.0.0.1").allowed).toBe(false);
    expect(checkSsrf("http://127.1.2.3:9200").allowed).toBe(false);
  });

  it("blocks private 10.x.x.x range", () => {
    expect(checkSsrf("http://10.0.0.1").allowed).toBe(false);
    expect(checkSsrf("http://10.255.255.255").allowed).toBe(false);
  });

  it("blocks 172.16–31.x.x range", () => {
    expect(checkSsrf("http://172.16.0.1").allowed).toBe(false);
    expect(checkSsrf("http://172.31.255.254").allowed).toBe(false);
    expect(checkSsrf("http://172.15.0.1").allowed).toBe(true); // outside range
  });

  it("blocks 192.168.x.x range", () => {
    expect(checkSsrf("http://192.168.0.1").allowed).toBe(false);
    expect(checkSsrf("http://192.168.100.200").allowed).toBe(false);
  });

  it("blocks AWS metadata endpoint", () => {
    expect(checkSsrf("http://169.254.169.254/latest/meta-data/").allowed).toBe(false);
    expect(checkSsrf("http://169.254.169.254").allowed).toBe(false);
  });

  it("blocks GCP metadata endpoint", () => {
    expect(checkSsrf("http://metadata.google.internal").allowed).toBe(false);
    expect(checkSsrf("http://metadata/computeMetadata/v1/").allowed).toBe(false);
  });

  it("blocks non-http schemes", () => {
    expect(checkSsrf("file:///etc/passwd").allowed).toBe(false);
    expect(checkSsrf("ftp://internal.server").allowed).toBe(false);
    expect(checkSsrf("gopher://evil.com").allowed).toBe(false);
  });

  it("rejects invalid URLs", () => {
    expect(checkSsrf("not-a-url").allowed).toBe(false);
    expect(checkSsrf("").allowed).toBe(false);
  });

  it("returns reason for blocked URLs", () => {
    const result = checkSsrf("http://127.0.0.1");
    expect(result.allowed).toBe(false);
    expect(result.reason).toBeTruthy();
  });
});
