export { runTestSuites, getTestRun, getTestRunHistory, testEvents } from "./runner";
export type { TestSuite, TestCase, TestResult, TestRun, TestContext } from "./types";

export { authSuite } from "./auth-test";
export { apiSuite } from "./api-test";
export { rbacSuite } from "./rbac-test";
export { functionalSuite } from "./functional-test";
export { securitySuite } from "./security-test";
export { databaseSuite } from "./database-test";
export { performanceSuite } from "./performance-test";
export { uiuxSuite } from "./uiux-test";
export { regressionSuite } from "./regression-test";

import { TestSuite } from "./types";
import { authSuite } from "./auth-test";
import { apiSuite } from "./api-test";
import { rbacSuite } from "./rbac-test";
import { functionalSuite } from "./functional-test";
import { securitySuite } from "./security-test";
import { databaseSuite } from "./database-test";
import { performanceSuite } from "./performance-test";
import { uiuxSuite } from "./uiux-test";
import { regressionSuite } from "./regression-test";

export const ALL_SUITES: TestSuite[] = [
  authSuite,
  apiSuite,
  rbacSuite,
  functionalSuite,
  securitySuite,
  databaseSuite,
  performanceSuite,
  uiuxSuite,
  regressionSuite,
];

export function getSuite(id: string): TestSuite | undefined {
  return ALL_SUITES.find(s => s.id === id);
}
