import rateLimit from "express-rate-limit";

// Auth rate limiter: 10 attempts per 15 min
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: "Too many attempts, please try again in 15 minutes" },
  standardHeaders: true,
  legacyHeaders: false,
});

// AI rate limiter: 30 requests per minute
export const aiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: "AI rate limit exceeded. Please wait." },
  standardHeaders: true,
  legacyHeaders: false,
});

// Scan creation limiter: 5 per minute
export const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: "Too many scans created. Please wait 1 minute." },
  standardHeaders: true,
  legacyHeaders: false,
});

// Global API limiter: 100 per minute
export const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: "Too many requests. Please slow down." },
  standardHeaders: true,
  legacyHeaders: false,
});
