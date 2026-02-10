
import dotenv from "dotenv";
dotenv.config({ path: "./data/config.env" });

import { createClient } from "@libsql/client";

export const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

export const connectDB = async () => {
  try {
    await db.execute("SELECT 1");
    console.log("✅ SQLite (Turso) connected successfully");
  } catch (error) {
    console.error("❌ SQLite connection failed:", error);
    process.exit(1);
  }
};
