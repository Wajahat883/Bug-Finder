import bcrypt from "bcryptjs";
import { col, ObjectId } from "./db";
import { logger } from "./logger";

export async function seedData() {
  // Always ensure the default admin user exists (idempotent)
  const adminEmail = "Waji2156@gmail.com";
  const adminPassword = "Waji2156..";
  const adminExists = await col("users").findOne({ email: adminEmail });
  if (!adminExists) {
    logger.info("Creating default admin user...");
    const hashed = await bcrypt.hash(adminPassword, 10);
    await col("users").insertOne({
      _id: new ObjectId(),
      username: "waji_admin",
      email: adminEmail,
      password: hashed,
      role: "admin",
      first_name: "Waji",
      last_name: "Admin",
      created_at: new Date(),
      updated_at: new Date(),
    });
    logger.info(`Default admin user created — email: ${adminEmail}, password: ${adminPassword}`);
  }

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
