import cron from "node-cron";
import { generatePDF } from "./pdfGenerator.js";
import { signBuffer } from "./signer.js";

import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
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
  cron.schedule("*/1 * * * *", async () => {
    console.log("🔁 Checking for pending transfers...");

    try {
const result = await db.execute({
  sql: `
    SELECT *
    FROM transfers
    WHERE status IN ('downloaded', 'delivered')
    ORDER BY delivered_at ASC
    LIMIT 5
  `,
});

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
  // ===== Fetch Sender Info =====
const senderResult = await db.execute({
  sql: `SELECT first_name, last_name, email, company_name FROM users WHERE id = ? LIMIT 1`,
  args: [transfer.sender_id],
});

const sender = senderResult.rows?.[0] || {};

const senderName = [sender.first_name, sender.last_name]
  .filter(Boolean)
  .join(" ");

let signatureSignedUrl = null;

if (transfer.digital_signature_url) {
  try {
    const key = transfer.digital_signature_url.split(`${BUCKET}/`)[1];

    const command = new GetObjectCommand({
      Bucket: BUCKET,
      Key: key,
    });

    signatureSignedUrl = await getSignedUrl(s3, command, {
      expiresIn: 60 * 10, // 10 minutes
    });
  } catch (err) {
    console.error("❌ Failed to generate signed URL:", err);
  }
}


// ===== Build dynamic transferData for PDF =====
const transferData = {
  // ======================
  // PLAN INFO
  // ======================
  plan_name: transfer.security_level || "Standard",
  audit_id: transfer.id,

  // ======================
  // CORE
  // ======================
  id: transfer.id,
  created_at: transfer.created_at,
  signature_date:
    transfer.download_used_at ||
    transfer.last_access_at ||
    transfer.delivered_at,

  verification_timestamp:
    transfer.delivered_at ||
    transfer.first_access_at,

  // ======================
  // AGREEMENT
  // ======================
  agreement_type: transfer.agreement_type, // one_click | signature
  verification_method: transfer.verification_method, // email | sms | email_sms | id_verification

  // ======================
  // SENDER
  // ======================
  sender_org: sender.company_name || "TransferGuard",
  sender_name: senderName || "Unknown Sender",
  sender_email: sender.email || "",
  verified_domain: sender.email?.split("@")[1] || "",

  // ======================
  // RECEIVER
  // ======================
  recipient_name: transfer.recipient_name,
  recipient_email: transfer.recipient_email,

  // ======================
  // FILE
  // ======================
  file_name: files?.name || "Unknown_File",
  file_size_bytes: transfer.total_size_bytes,
  sha256_hash:
    transfer.sha256_hash ||
    transfer.encrypted_password ||
    "Not Available",

  // ======================
  // TRANSFER STATUS
  // ======================
  transfer_status:
    transfer.status === "signed"
      ? "Digitally Signed & Certified"
      : "Successfully Delivered & Verified",

  chosen_verification: transfer.verification_method,

  // ======================
  // VERIFICATION DETAILS
  // ======================
  email_verified_at: transfer.email_verified_at,
sms_verified_at: transfer.sms_verified_at,
  email_address: transfer.recipient_email,
  telephone_number: transfer.recipient_phone, // set later if you store it
signature_url: signatureSignedUrl,
signature_date:
  transfer.receipt_accepted_at ||
  transfer.sms_verified_at ||
  transfer.email_verified_at,
  unique_token_id: transfer.download_token,

  // ======================
  // ID VERIFICATION (only used if id_verification)
  // ======================
  id_type:
    transfer.verification_method === "id_verification"
      ? "Government Issued ID"
      : null,

  last_digits_iddocument: "e4db",
  biometric_match:
    transfer.verification_method === "id_verification"
      ? "Successful"
      : null,

  veriff_session_id: null,
  external_timestamp: transfer.delivered_at,

  // ======================
  // SIGNATURE
  // ======================
  signature_name: transfer.recipient_name,

  // ======================
  // TECHNICAL AUDIT
  // ======================
  ip_address:
    transfer.last_access_ip ||
    audit.ip_address ||
    "0.0.0.0",

  location: `${audit.city || "Unknown"}, ${audit.country || ""}`,
  browser: audit.user_agent || "",

  // ======================
  // LEGAL / COMPLIANCE
  // ======================
  tsa_provider: "Qualified Sectigo TSA",
  encryption_standard:
    transfer.encrypted_password
      ? "AES-256 End-to-End Encryption"
      : "Standard TLS Encryption",

  terms_version: "v1.4",
  privacy_version: "v1.2",
};

          // 1️⃣ Generate PDF
          const pdfBuffer = await generatePDF(transferData);

          // 2️⃣ HSM Sign
          const signedBuffer = await signBuffer(pdfBuffer);


          // 4️⃣ Upload to OVH
          const key = `signed-audit/${transfer.id}.pdf`;

          await s3.send(
            new PutObjectCommand({
              Bucket: BUCKET,
              Key: key,
             Body: signedBuffer,
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
