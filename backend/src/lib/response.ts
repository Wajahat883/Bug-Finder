/**
 * RFC 7807 Problem Details — consistent error and success responses.
 * All routes should use these helpers instead of raw res.json / res.status.
 */
import type { Response } from "express";

export interface ProblemDetail {
  type: string;
  title: string;
  status: number;
  detail?: string;
  instance?: string;
  [key: string]: unknown;
}

export function errorResponse(
  res: Response,
  status: number,
  title: string,
  detail?: string,
  extra?: Record<string, unknown>
): void {
  const body: ProblemDetail = {
    type: `https://bugfinder.local/errors/${title.toLowerCase().replace(/\s+/g, "-")}`,
    title,
    status,
    ...(detail ? { detail } : {}),
    ...(extra ?? {}),
  };
  res.status(status).contentType("application/problem+json").json(body);
}

export function successResponse<T>(res: Response, data: T, status = 200): void {
  res.status(status).json(data);
}
