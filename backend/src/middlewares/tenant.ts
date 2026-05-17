/**
 * Multi-Tenant Middleware — injects tenant_id into every request.
 *
 * Tenant resolution order:
 *   1. X-Tenant-ID header (for API clients)
 *   2. Subdomain (tenant.bugfinder.com)
 *   3. User's tenant_id from session/DB
 *   4. "default" (single-tenant mode when MULTI_TENANT=false)
 */
import type { Request, Response, NextFunction } from "express";
import { col, ObjectId } from "../lib/db";

declare module "express" {
  interface Request {
    tenantId?: string;
  }
}

const MULTI_TENANT = process.env["MULTI_TENANT"] === "true";

export async function tenantMiddleware(req: Request, _res: Response, next: NextFunction): Promise<void> {
  if (!MULTI_TENANT) {
    req.tenantId = "default";
    return next();
  }

  // 1. Explicit header (API clients / CI-CD)
  const headerTenant = req.headers["x-tenant-id"] as string | undefined;
  if (headerTenant) {
    req.tenantId = headerTenant;
    return next();
  }

  // 2. Subdomain resolution
  const host = req.hostname ?? "";
  const parts = host.split(".");
  if (parts.length >= 3) {
    req.tenantId = parts[0]; // tenant.bugfinder.com → "tenant"
    return next();
  }

  // 3. Tenant from authenticated user
  const session = (req as unknown as { session: Record<string, unknown> }).session;
  if (session?.userId) {
    try {
      const user = await col("users").findOne({ _id: new ObjectId(String(session.userId)) }) as Record<string, unknown> | null;
      if (user?.tenant_id) {
        req.tenantId = String(user.tenant_id);
        return next();
      }
    } catch { /* non-fatal */ }
  }

  req.tenantId = "default";
  next();
}

/**
 * Inject tenant_id filter into a MongoDB query.
 * Use in every route that reads from shared collections.
 */
export function withTenant(query: Record<string, unknown>, tenantId?: string): Record<string, unknown> {
  if (!MULTI_TENANT || !tenantId || tenantId === "default") return query;
  return { ...query, tenant_id: tenantId };
}
