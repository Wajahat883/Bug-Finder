import type { Request, Response, NextFunction } from "express";

interface SessionData {
  userId?: string;
  role?: string;
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const session = (req as unknown as { session: SessionData }).session;
  if (!session?.userId) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }
  next();
}

export function requireRole(...roles: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const session = (req as unknown as { session: SessionData }).session;
    if (!session?.userId) {
      res.status(401).json({ error: "Authentication required" });
      return;
    }
    if (!roles.includes(session.role ?? "")) {
      res.status(403).json({ error: "Insufficient permissions" });
      return;
    }
    next();
  };
}

export const requireAdmin = requireRole("admin");
