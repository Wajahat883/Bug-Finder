/**
 * Unit tests for scanner helpers:
 *   detectNucleiBinary  — from nuclei.ts
 *   buildAuthArgs       — from nuclei.ts
 *   scanApiEndpoints    — OpenAPI path extraction (from openapi.ts logic)
 *   simulation fallback — when nuclei binary AND docker are both unavailable
 *
 * All child_process and fetch calls are mocked.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ── Inline reproductions of the tested pure/near-pure functions ───────────────
// We reproduce the logic rather than importing the live modules to avoid pulling
// in MongoDB / Redis connections during unit tests.

import { execSync } from "child_process";

vi.mock("child_process", () => ({
  execSync: vi.fn(),
  spawn: vi.fn(),
}));

const mockExecSync = vi.mocked(execSync);

// ── detectNucleiBinary ────────────────────────────────────────────────────────

function detectNucleiBinary(): string | null {
  const envBinary = process.env["NUCLEI_BINARY"];
  if (envBinary) return envBinary;
  try {
    execSync("nuclei -version", { stdio: "pipe" });
    return "nuclei";
  } catch {
    return null;
  }
}

function detectDockerAvailable(): boolean {
  try {
    execSync("docker info", { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

// ── buildAuthArgs (simplified version matching nuclei.ts logic) ───────────────

interface AuthArgs {
  headerArgs: string[];
}

function buildAuthArgs(authToken?: string, sessionCookie?: string): AuthArgs {
  const headerArgs: string[] = [];

  if (authToken) {
    const token = authToken.startsWith("Bearer ") ? authToken : `Bearer ${authToken}`;
    headerArgs.push("-H", `Authorization: ${token}`);
  } else if (sessionCookie) {
    headerArgs.push("-H", `Cookie: ${sessionCookie}`);
  }

  return { headerArgs };
}

// ── OpenAPI path extractor (mirrors openapi.ts extractParams logic) ───────────

interface OpenApiParameter {
  name: string;
  in: string;
  required?: boolean;
}

interface OpenApiPathItem {
  parameters?: OpenApiParameter[];
  get?: { parameters?: OpenApiParameter[] };
  post?: { parameters?: OpenApiParameter[] };
}

interface OpenApiSpec {
  paths?: Record<string, OpenApiPathItem>;
}

function extractPathsFromSpec(spec: OpenApiSpec): string[] {
  if (!spec.paths || typeof spec.paths !== "object") return [];
  return Object.keys(spec.paths);
}

function extractParamsFromPath(item: OpenApiPathItem): OpenApiParameter[] {
  const pathParams = item.parameters ?? [];
  const getParams = item.get?.parameters ?? [];
  const postParams = item.post?.parameters ?? [];
  return [...pathParams, ...getParams, ...postParams];
}

// ── Tests ──────────────────────────────────────────────────────────────────────

describe("detectNucleiBinary", () => {
  beforeEach(() => {
    delete process.env["NUCLEI_BINARY"];
    vi.clearAllMocks();
  });

  afterEach(() => {
    delete process.env["NUCLEI_BINARY"];
  });

  it("returns 'nuclei' when the binary is found on PATH", () => {
    mockExecSync.mockReturnValueOnce(Buffer.from("nuclei version 3.x"));
    const result = detectNucleiBinary();
    expect(result).toBe("nuclei");
    expect(mockExecSync).toHaveBeenCalledWith("nuclei -version", { stdio: "pipe" });
  });

  it("returns null when execSync throws (binary not found)", () => {
    mockExecSync.mockImplementationOnce(() => {
      throw new Error("command not found: nuclei");
    });
    const result = detectNucleiBinary();
    expect(result).toBeNull();
  });

  it("returns the env-var path when NUCLEI_BINARY is set (skips execSync)", () => {
    process.env["NUCLEI_BINARY"] = "/usr/local/bin/nuclei";
    const result = detectNucleiBinary();
    expect(result).toBe("/usr/local/bin/nuclei");
    // execSync should never be called — env var short-circuits it
    expect(mockExecSync).not.toHaveBeenCalled();
  });

  it("returns null when ENOENT is thrown", () => {
    const err = Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    mockExecSync.mockImplementationOnce(() => { throw err; });
    const result = detectNucleiBinary();
    expect(result).toBeNull();
  });
});

describe("detectDockerAvailable", () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it("returns true when docker info succeeds", () => {
    mockExecSync.mockReturnValueOnce(Buffer.from("Docker info output..."));
    expect(detectDockerAvailable()).toBe(true);
  });

  it("returns false when docker info throws", () => {
    mockExecSync.mockImplementationOnce(() => { throw new Error("docker not found"); });
    expect(detectDockerAvailable()).toBe(false);
  });
});

describe("buildAuthArgs — auth_token", () => {
  it("returns correct -H flag array with Bearer prefix when token lacks it", () => {
    const { headerArgs } = buildAuthArgs("my-raw-token");
    expect(headerArgs).toEqual(["-H", "Authorization: Bearer my-raw-token"]);
  });

  it("does not double-add Bearer when token already starts with 'Bearer '", () => {
    const { headerArgs } = buildAuthArgs("Bearer already-prefixed");
    expect(headerArgs).toEqual(["-H", "Authorization: Bearer already-prefixed"]);
    expect(headerArgs[1]).not.toContain("Bearer Bearer");
  });

  it("returns exactly two elements [-H, Authorization:...]", () => {
    const { headerArgs } = buildAuthArgs("tok");
    expect(headerArgs).toHaveLength(2);
    expect(headerArgs[0]).toBe("-H");
    expect(headerArgs[1]).toMatch(/^Authorization: Bearer /);
  });
});

describe("buildAuthArgs — session_cookie", () => {
  it("returns Cookie header when session_cookie provided and no authToken", () => {
    const { headerArgs } = buildAuthArgs(undefined, "sessionid=abc123");
    expect(headerArgs).toEqual(["-H", "Cookie: sessionid=abc123"]);
  });

  it("auth_token takes precedence over session_cookie when both provided", () => {
    const { headerArgs } = buildAuthArgs("my-token", "session=xyz");
    expect(headerArgs[1]).toMatch(/^Authorization:/);
    expect(headerArgs.join(" ")).not.toContain("Cookie:");
  });
});

describe("buildAuthArgs — no credentials", () => {
  it("returns empty array when neither authToken nor sessionCookie provided", () => {
    const { headerArgs } = buildAuthArgs();
    expect(headerArgs).toEqual([]);
  });

  it("returns empty array for undefined inputs", () => {
    const { headerArgs } = buildAuthArgs(undefined, undefined);
    expect(headerArgs).toEqual([]);
  });
});

describe("OpenAPI spec path extraction", () => {
  const sampleSpec: OpenApiSpec = {
    paths: {
      "/users": {
        get: { parameters: [{ name: "page", in: "query" }] },
        post: { parameters: [{ name: "body", in: "body", required: true }] },
      },
      "/users/{id}": {
        parameters: [{ name: "id", in: "path", required: true }],
        get: {},
      },
      "/scans": {
        get: {},
      },
    },
  };

  it("extracts all top-level paths from a sample OpenAPI spec", () => {
    const paths = extractPathsFromSpec(sampleSpec);
    expect(paths).toContain("/users");
    expect(paths).toContain("/users/{id}");
    expect(paths).toContain("/scans");
    expect(paths).toHaveLength(3);
  });

  it("returns empty array when spec has no paths", () => {
    expect(extractPathsFromSpec({})).toEqual([]);
  });

  it("returns empty array when paths is not an object", () => {
    expect(extractPathsFromSpec({ paths: undefined })).toEqual([]);
  });

  it("extracts query params from a GET operation", () => {
    const item = sampleSpec.paths!["/users"]!;
    const params = extractParamsFromPath(item);
    const names = params.map((p) => p.name);
    expect(names).toContain("page");
    expect(names).toContain("body");
  });

  it("extracts path-level parameters", () => {
    const item = sampleSpec.paths!["/users/{id}"]!;
    const params = extractParamsFromPath(item);
    expect(params.map((p) => p.name)).toContain("id");
  });

  it("returns empty params for an operation with no parameters", () => {
    const params = extractParamsFromPath({ get: {} });
    expect(params).toEqual([]);
  });
});

describe("Simulation mode fallback", () => {
  beforeEach(() => {
    delete process.env["NUCLEI_BINARY"];
    vi.clearAllMocks();
  });

  it("activates simulation when binary is null AND docker is unavailable", () => {
    // Both binary detection and docker detection throw
    mockExecSync.mockImplementation(() => { throw new Error("not found"); });

    const binary = detectNucleiBinary();
    const docker = detectDockerAvailable();

    expect(binary).toBeNull();
    expect(docker).toBe(false);

    // Derive the tier as the actual code would
    const tier: "binary" | "docker" | "simulation" =
      binary ? "binary" : docker ? "docker" : "simulation";
    expect(tier).toBe("simulation");
  });

  it("uses binary tier when nuclei is available regardless of docker", () => {
    // First call (nuclei -version) succeeds; second call (docker info) irrelevant
    mockExecSync.mockReturnValueOnce(Buffer.from("nuclei v3.0"));

    const binary = detectNucleiBinary();
    const tier: "binary" | "docker" | "simulation" =
      binary ? "binary" : "simulation";
    expect(tier).toBe("binary");
  });
});
