import { col } from "./db";
import { logger } from "./logger";

export async function seedData() {
  const settingsCol = col("settings");

  const existing = await settingsCol.findOne({});
  if (existing) {
    logger.info("Database already seeded, skipping");
    return;
  }

  logger.info("Seeding initial settings...");

  await settingsCol.insertOne({
    default_export_format: "json",
    notifications_enabled: true,
    ai_analysis_enabled: true,
    max_concurrent_scans: 5,
    webhook_url: "",
    api_key: `bbp_${Math.random().toString(36).substring(2, 18)}`,
    github_login: "Wajahat883",
    created_at: new Date(),
    updated_at: new Date(),
  });

  logger.info("Settings seeded successfully");
}
