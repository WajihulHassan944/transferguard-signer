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

  // ---------------------------
  // Build dynamic location
  // ---------------------------
  const location = [audit.city, audit.region, audit.country]
    .filter(Boolean)
    .join(", ");

  // ---------------------------
  // Replace template placeholders
  // ---------------------------
  html = html
    // ======================
    // SECTION 0 - SENDER INFO
    // ======================
    .replaceAll("{{SENDER_ORG}}", escape(data.sender_org))
    .replaceAll("{{SENDER_NAME}}", escape(data.sender_name))
    .replaceAll("{{SENDER_EMAIL}}", escape(data.sender_email))
    .replaceAll("{{DATE_SENT}}", formatDate(data.created_at))

    // ======================
    // SECTION 1 - TRANSFER
    // ======================
    .replaceAll("{{FILE_NAME}}", escape(data.files?.[0]?.name))
    .replaceAll("{{SHA256}}", escape(data.sha256_hash))
    .replaceAll(
      "{{FILE_SIZE}}",
      escape(data.files?.[0]?.size
        ? data.files[0].size + " bytes"
        : "")
    )
    .replaceAll(
      "{{TRANSFER_STATUS}}",
      escape(data.status ?? "Successfully Downloaded & Identity Verified")
    )

    // ======================
    // SECTION 2 - IDENTITY
    // ======================
    .replaceAll("{{RECIPIENT_NAME}}", escape(data.recipient_name))
    .replaceAll("{{ID_TYPE}}", escape(data.id_type))
    .replaceAll("{{ID_NUMBER}}", escape(data.id_number))
    .replaceAll("{{BIOMETRIC}}", escape(data.biometric_result))
    .replaceAll("{{VERIFF_SESSION}}", escape(data.veriff_session))
    .replaceAll("{{IDV_TIME}}", formatDate(data.idv_timestamp))

    // ======================
    // SIGNATURE
    // ======================
    .replaceAll("{{SIGNATURE_URL}}", escape(data.signatureUrl))
    .replaceAll("{{SIGN_DATE}}", formatDate(data.signDate))

    // ======================
    // TECHNICAL AUDIT
    // ======================
    .replaceAll("{{IP}}", escape(data.last_access_ip ?? audit.ip_address))
    .replaceAll("{{LOCATION}}", escape(location))
    .replaceAll("{{DEVICE}}", escape(audit.device_type))
    .replaceAll("{{BROWSER}}", escape(audit.user_agent))

    // ======================
    // AUDIT ID
    // ======================
    .replaceAll("{{AUDIT_ID}}", escape(data.id));

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
    top: "26mm",    // Restored original top margin
    bottom: "28mm", // Slightly larger to clear the multi-line footer
    left: "22mm",   // Restored original left margin
    right: "22mm"   // Restored original right margin
  },
  headerTemplate: '<div></div>', 
  footerTemplate: `
    <div style="font-family: 'Inter', Arial; font-size: 10px; width: 100%; text-align: center; color: #444; padding-bottom: 5px;">
      <div style="margin-bottom: 4px;">
        TransferGuard Legal Plan - Audit ID: <span class="title"></span> — Page <span class="pageNumber"></span> of <span class="totalPages"></span>
      </div>
      <div>TransferGuard is part of PVG Technologies BV, The Netherlands</div>
    </div>
  `,
  preferCSSPageSize: false, 
});

  await browser.close();
  return Buffer.from(pdf);
}