import app from "./app";
import { logger } from "./lib/logger";

// Refuse to start in production with default/insecure secret values
if (process.env["NODE_ENV"] === "production") {
  const INSECURE_DEFAULTS = [
    ["SESSION_SECRET", "bug-finder-secret-change-in-prod"],
    ["ADMIN_PASSWORD", "Admin123!"],
    ["CREDENTIAL_VAULT_KEY", "dev-credential-vault-key-min-32-chars!"],
    ["WEBHOOK_SECRET_KEY", "dev-webhook-secret-key-32-chars!!"],
  ] as const;
  for (const [key, defaultVal] of INSECURE_DEFAULTS) {
    if (!process.env[key] || process.env[key] === defaultVal) {
      logger.error({ key }, `STARTUP BLOCKED: ${key} is using an insecure default value. Set a strong secret before deploying.`);
      process.exit(1);
    }
  }
}

const rawPort = process.env["PORT"];

if (!rawPort) {
  throw new Error(
    "PORT environment variable is required but was not provided.",
  );
}

const port = Number(rawPort);

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

app.listen(port, (err) => {
  if (err) {
    logger.error({ err }, "Error listening on port");
    process.exit(1);
  }

  logger.info({ port }, "Server listening");
});
