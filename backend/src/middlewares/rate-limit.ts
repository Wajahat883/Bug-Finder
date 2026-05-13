import rateLimit from "express-rate-limit";

let _testMode = false;
export function enableTestMode() { _testMode = true; }
export function disableTestMode() { _testMode = false; }

function skipIfTest(): (req: unknown) => boolean {
  return () => _testMode;
}

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: "Too many attempts, please try again in 15 minutes" },
  standardHeaders: true,
  legacyHeaders: false,
  skip: skipIfTest(),
});

export const aiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: "AI rate limit exceeded. Please wait." },
  standardHeaders: true,
  legacyHeaders: false,
  skip: skipIfTest(),
});

export const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: "Too many scans created. Please wait 1 minute." },
  standardHeaders: true,
  legacyHeaders: false,
  skip: skipIfTest(),
});

export const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: "Too many requests. Please slow down." },
  standardHeaders: true,
  legacyHeaders: false,
  skip: skipIfTest(),
});
