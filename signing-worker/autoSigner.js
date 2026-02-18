import cron from "node-cron";
import { generatePDF } from "./pdfGenerator.js";
import { signBuffer } from "./signer.js";
import { applyTimestamp } from "./tsa.js";

import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { NodeHttpHandler } from "@aws-sdk/node-http-handler";
import https from "https";
import { db } from "../data/database.js";

// ===== OVH CONFIG =====
const BUCKET = "transferguard";
const REGION = "de";
const ENDPOINT = "https://s3.de.io.cloud.ovh.net";

const s3 = new S3Client({
  region: REGION,
  endpoint: ENDPOINT,
  credentials: {
    accessKeyId: process.env.OVH_ACCESS_KEY,
    secretAccessKey: process.env.OVH_SECRET_KEY,
  },
  forcePathStyle: true,
  requestHandler: new NodeHttpHandler({
    httpsAgent: new https.Agent({
      keepAlive: true,
      maxSockets: 50,
      keepAliveMsecs: 30000,
    }),
  }),
});

// ===== CRON JOB (every 2 minutes) =====
export function startAutoSigner() {
  cron.schedule("*/2 * * * *", async () => {
    console.log("🔁 Checking for pending transfers...");

    try {
      const result = await db.execute(
      `SELECT * FROM transfers WHERE status != 'signed' LIMIT 5`
);

      const transfers = result.rows;

      if (!transfers.length) {
        console.log("✅ No pending transfers");
        return;
      }

      for (const transfer of transfers) {
        try {
          console.log("📄 Processing transfer:", transfer.id);

          const files = JSON.parse(transfer.files_json || "{}");

          // ===== Parse audit_log_json for dynamic fields =====
          let audit = {};
          try {
            audit =
              typeof transfer.audit_log_json === "string"
                ? JSON.parse(transfer.audit_log_json)
                : transfer.audit_log_json || {};
          } catch {
            audit = {};
          }

          // ===== Build dynamic transferData for PDF =====
          const transferData = {
            sha256: transfer.sha256_hash || transfer.encrypted_password,
            fileSize: transfer.total_size_bytes,
            files: [files],
            recipient: {
              name: transfer.recipient_email,
              idType: transfer.security_level || null,
              idNumber: transfer.dossier_number || null,
              biometric: transfer.qerds_certified || null,
              veriffSession: transfer.decryption_token || null,
              idvTime: transfer.delivered_at || null,
            },
            signatureUrl: transfer.signatureUrl || "https://transferguard.com/signature.png",
            signDate: transfer.signDate || new Date().toISOString(),
            ip: transfer.last_access_ip || audit.ip_address || "0.0.0.0",
            location: [audit.city, audit.region, audit.country].filter(Boolean).join(", "),
            device: audit.device_type || "unknown",
            browser: audit.user_agent || "unknown",
          };

          // 1️⃣ Generate PDF
          const pdfBuffer = await generatePDF(transferData);

          // 2️⃣ HSM Sign
          const signedBuffer = await signBuffer(pdfBuffer);

          // 3️⃣ TSA Timestamp
          const finalBuffer = await applyTimestamp(signedBuffer);

          // 4️⃣ Upload to OVH
          const key = `signed-audit/${transfer.id}.pdf`;

          await s3.send(
            new PutObjectCommand({
              Bucket: BUCKET,
              Key: key,
              Body: finalBuffer,
              ContentType: "application/pdf",
            })
          );

          console.log("☁ Uploaded signed PDF to OVH:", key);

          // 5️⃣ Update DB
          await db.execute({
            sql: `
              UPDATE transfers
              SET status = 'signed',
                  audit_enabled = 1,
                  updated_at = CURRENT_TIMESTAMP
              WHERE id = ?
            `,
            args: [transfer.id],
          });

          console.log("✅ Transfer signed & updated:", transfer.id);
        } catch (err) {
          console.error("❌ Failed for transfer:", transfer.id, err);
        }
      }
    } catch (err) {
      console.error("❌ Cron error:", err);
    }
  });
}
