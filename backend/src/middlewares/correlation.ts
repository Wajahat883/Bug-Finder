// POINT 9: Correlation IDs — every request gets a unique trace ID
import type { Request, Response, NextFunction } from "express";
import { randomUUID } from "crypto";

declare module "express" {
  interface Request {
    correlationId?: string;
  }
}

export function correlationMiddleware(req: Request, res: Response, next: NextFunction): void {
  const id = (req.headers["x-correlation-id"] as string) || (req.headers["x-request-id"] as string) || randomUUID();
  req.correlationId = id;
  res.setHeader("X-Correlation-ID", id);
  next();
}
