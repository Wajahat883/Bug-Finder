export type TestSeverity = "pass" | "fail" | "warn" | "error" | "skipped";

export type TestCategory =
  | "auth"
  | "api"
  | "rbac"
  | "functional"
  | "security"
  | "database"
  | "performance"
  | "uiux"
  | "regression";

export interface TestCase {
  id: string;
  category: TestCategory;
  name: string;
  description: string;
  run: (ctx: TestContext) => Promise<TestResult>;
  tags?: string[];
  timeout?: number;
}

export interface TestResult {
  id: string;
  name: string;
  category: TestCategory;
  status: TestSeverity;
  duration: number;
  message: string;
  details?: string;
  evidence?: Record<string, unknown>;
  suggestion?: string;
}

export interface TestSuite {
  id: string;
  category: TestCategory;
  label: string;
  description: string;
  icon: string;
  tests: TestCase[];
}

export interface TestRun {
  id: string;
  startedAt: string;
  completedAt?: string;
  suites: string[];
  results: TestResult[];
  summary: {
    total: number;
    pass: number;
    fail: number;
    warn: number;
    error: number;
    skipped: number;
    duration: number;
  };
  status: "running" | "completed" | "failed";
}

export interface TestContext {
  baseUrl: string;
  apiBase: string;
  session?: { userId: string; username: string; role: string };
  cookies?: string;
  headers?: Record<string, string>;
  cookieStore: Map<string, string>;
  runtime: {
    startTime: number;
    collectedData: Map<string, unknown>;
    warnings: string[];
  };
}
