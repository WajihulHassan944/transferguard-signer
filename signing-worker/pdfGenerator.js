import puppeteer from "puppeteer";
import fs from "fs";
import path from "path";

export async function generatePDF(data) {
  const templatePath = path.resolve("signing-worker/template.html");
  let html = fs.readFileSync(templatePath, "utf8");

  // ---------------------------
  // Safe Escape Function
  // ---------------------------
  const escape = (v) =>
    String(v ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;");

  const formatDate = (d) => {
    if (!d) return "";
    try {
      return (
        new Date(d).toLocaleString("en-GB", {
          hour12: false,
          day: "2-digit",
          month: "2-digit",
          year: "numeric",
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }) + " CET"
      );
    } catch {
      return "";
    }
  };

  // ---------------------------
  // Convert file size (MB/GB/TB)
  // ---------------------------
  const formatFileSize = (bytes) => {
    if (!bytes) return "";
    const gb = bytes / (1024 ** 3);
    const tb = bytes / (1024 ** 4);
    const mb = bytes / (1024 ** 2);

    if (tb >= 1) return tb.toFixed(2) + " TB";
    if (gb >= 1) return gb.toFixed(2) + " GB";
    return mb.toFixed(2) + " MB";
  };

  // ---------------------------
  // Parse audit_log_json safely
  // ---------------------------
  let audit = {};
  try {
    audit =
      typeof data.audit_log_json === "string"
        ? JSON.parse(data.audit_log_json)
        : data.audit_log_json || {};
  } catch {
    audit = {};
  }

  const location = [audit.city, audit.region, audit.country]
    .filter(Boolean)
    .join(", ");

  // ============================================================
  // PROFESSIONAL PLAN (EMAIL VERIFICATION ONLY)
  // ============================================================

  html = html

    // ======================
    // PLAN TITLE
    // ======================
    .replaceAll("{{PLAN_NAME}}", escape(data.plan_name))

    // ======================
    // 1. SENDER INFORMATION
    // ======================
    .replaceAll("{{name_organisation_sender}}", escape(data.sender_org))
    .replaceAll("{{sender_name}}", escape(data.sender_name))
    .replaceAll("{{sender_email}}", escape(data.sender_email))
    .replaceAll("{{verified_domain}}", escape(data.verified_domain))
    .replaceAll("{{TIME_DATE_SEND}}", formatDate(data.time_date_send))

    // ======================
    // 2. RECEIVER INFORMATION
    // ======================
    .replaceAll("{{recipient_name}}", escape(data.recipient_name))
    .replaceAll("{{recipient_email}}", escape(data.recipient_email))
    .replaceAll("{{TIME_DATE_RECEIVED}}", formatDate(data.time_date_received))

    // ======================
    // 3. TRANSFER SUMMARY
    // ======================
    .replaceAll("{{FiLE_NAME}}", escape(data.file_name))
    .replaceAll("{{HASH}}", escape(data.sha256_hash))
    .replaceAll("{{FILE_SIZE}}", escape(formatFileSize(data.file_size_bytes)))
    .replaceAll(
      "{{choosen_verification}}",
      escape(data.chosen_verification || "Email Verification")
    )

    // ======================
    // 4. VERIFIED BY EMAIL (PROFESSIONAL PLAN)
    // ======================
    .replaceAll("{{email adress}}", escape(data.recipient_email))
    .replaceAll(
      "{{verification timestamp}}",
      formatDate(data.verification_timestamp)
    )
    .replaceAll("{{Uniqie Token ID}}", escape(data.unique_token_id))

    // ======================
    // 5. ELECTRONIC CONSENT
    // ======================
    .replaceAll("{{SIGNATURE_NAME}}", escape(data.signature_name))
    .replaceAll("{{SIGN_DATE}}", formatDate(data.signature_date))

    // ======================
    // TECHNICAL AUDIT LOG
    // ======================
    .replaceAll("{{IP_ADDRESS}}", escape(data.ip_address))
    .replaceAll("{{LOCATION}}", escape(location))
    .replaceAll("{{DEVICE_OS}}", escape(audit.device_type))
    .replaceAll("{{BROWSER}}", escape(audit.user_agent))

    // ======================
    // LEGAL COMPLIANCE
    // ======================
    .replaceAll("{{TSA_PROVIDER}}", escape(data.tsa_provider))
    .replaceAll("{{ENCRYPTION_STANDARD}}", escape(data.encryption_standard))
    .replaceAll("{{TERMS_VERSION}}", escape(data.terms_version))
    .replaceAll("{{PRIVACY_VERSION}}", escape(data.privacy_version))

    // ======================
    // AUDIT ID
    // ======================
    .replaceAll("{{AUDIT_ID}}", escape(data.audit_id));

  // ============================================================
  // COMMENTED OUT (NOT USED IN PROFESSIONAL EMAIL PLAN)
  // ============================================================

  /*
  // ======================
  // SMS VERIFICATION (Business Plan)
  // ======================
  .replaceAll("{{telephone_number}}", escape(data.telephone_number))

  // ======================
  // MFA VERIFICATION (Enterprise Plan)
  // ======================
  .replaceAll("{{VERIFICATION_METHOD_C}}", escape(data.mfa))

  // ======================
  // BIOMETRIC ID VERIFICATION (Enterprise Plan)
  // ======================
  .replaceAll("{{ID_type}}", escape(data.id_type))
  .replaceAll("{{last_digits_iddocument}}", escape(data.last_digits_iddocument))
  .replaceAll("{{Biometric Match}}", escape(data.biometric_match))
  .replaceAll("{{Veriff_session_ID}}", escape(data.veriff_session_id))
  .replaceAll("{{external_timestamp}}", formatDate(data.external_timestamp))
  */

  // ---------------------------
  // Generate PDF
  // ---------------------------
  const browser = await puppeteer.launch({
    headless: "new",
    args: ["--no-sandbox", "--font-render-hinting=medium"],
  });

  const page = await browser.newPage();
  await page.setContent(html, { waitUntil: "networkidle0" });

  const pdf = await page.pdf({
    format: "A4",
    printBackground: true,
    displayHeaderFooter: true,
    margin: {
      top: "26mm",
      bottom: "30mm",
      left: "22mm",
      right: "22mm",
    },
    headerTemplate: "<div></div>",
    footerTemplate: `
      <center><div style="font-family: 'Inter', Arial; font-size: 12px; width: 70%; text-align: center; color: #444; padding: 0 20px;">
        <div style="margin-bottom: 4px;">
          This "Certificate of Evidence" is generated following a successful biometric identity verification and explicit digital signature. 
          The document is cryptographically sealed via the TransferGuard Legal Engine (PDF Signing) to ensure court-admissibility.
        </div>
        <div style="margin-bottom: 4px;">
          TransferGuard Legal Plan - Audit ID: <span class="title"></span> - Page 
          <span class="pageNumber"></span>
        </div>
        <div>
          TransferGuard is part of PVG Technologies BV, The Netherlands
        </div>
      </div></center>
    `,
    preferCSSPageSize: false,
  });

  await browser.close();
  return Buffer.from(pdf);
}