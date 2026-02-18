import puppeteer from "puppeteer";
import fs from "fs";
import path from "path";

export async function generatePDF(data) {
  const templatePath = path.resolve("signing-worker/template.html");
  let html = fs.readFileSync(templatePath, "utf8");

  const escape = (v) =>
    String(v ?? "") // render even if null
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;");

  const formatDate = (d) =>
    d ? new Date(d).toLocaleString("en-GB", { hour12: false }) + " CET" : "";

  // ---------------------------
  // Parse files_json
  // ---------------------------
  let parsedFiles = [];
  try {
    const fileObj =
      typeof data.files_json === "string"
        ? JSON.parse(data.files_json)
        : data.files_json;

    if (fileObj) {
      parsedFiles.push({
        name: fileObj.name,
        size: fileObj.size + " bytes",
        hash: data.sha256_hash,
      });
    }
  } catch (e) {
    parsedFiles = [];
  }

  const fileRows = parsedFiles
    .map(
      (f, i) => `
        <tr>
          <td>${i + 1}</td>
          <td>${escape(f.name)}</td>
          <td>${escape(f.size)}</td>
          <td class="mono">${escape(f.hash)}</td>
        </tr>`
    )
    .join("");

  // ---------------------------
  // Parse audit_log_json
  // ---------------------------
  let audit = {};
  try {
    audit =
      typeof data.audit_log_json === "string"
        ? JSON.parse(data.audit_log_json)
        : data.audit_log_json || {};
  } catch (e) {
    audit = {};
  }

  // ---------------------------
  // Replace template variables
  // ---------------------------
  html = html
    // File / Transfer Info
    .replaceAll("{{FILE_NAME}}", escape(parsedFiles[0]?.name))
    .replaceAll("{{SHA256}}", escape(data.sha256_hash))
    .replaceAll("{{FILE_SIZE}}", escape(data.total_size_bytes + " bytes"))
    .replaceAll("{{TRANSFER_STATUS}}", escape(data.status))

    // Recipient / Identity (from API if exists)
    .replaceAll("{{RECIPIENT_NAME}}", escape(data.recipient_email))
    .replaceAll("{{ID_TYPE}}", escape(data.security_level))
    .replaceAll("{{ID_NUMBER}}", escape(data.dossier_number))
    .replaceAll("{{BIOMETRIC}}", escape(data.qerds_certified))
    .replaceAll("{{VERIFF_SESSION}}", escape(data.decryption_token))
    .replaceAll("{{IDV_TIME}}", formatDate(data.delivered_at))

    // Signature (non-API fields — keep these dynamic)
    .replaceAll("{{SIGNATURE_URL}}", escape(data.signatureUrl))
    .replaceAll("{{SIGN_DATE}}", escape(data.signDate))

    // Audit / Access
    .replaceAll("{{IP}}", escape(data.last_access_ip ?? audit.ip_address))
    .replaceAll(
      "{{LOCATION}}",
      escape(
        [audit.city, audit.region, audit.country]
          .filter(Boolean)
          .join(", ")
      )
    )
    .replaceAll("{{DEVICE}}", escape(audit.device_type))
    .replaceAll("{{BROWSER}}", escape(audit.user_agent))

    // Audit ID (use transfer ID dynamically)
    .replaceAll("{{AUDIT_ID}}", escape(data.id))

    // Inject file rows if template uses table body
    .replace("{{FILE_ROWS}}", fileRows);

  // ---------------------------
  // Generate PDF
  // ---------------------------
  const browser = await puppeteer.launch({
    headless: "new",
    args: ["--no-sandbox", "--font-render-hinting=medium"],
  });

  const page = await browser.newPage();
  await page.setContent(html, { waitUntil: "load" });

  const pdf = await page.pdf({
    format: "A4",
    printBackground: true,
    margin: {
      top: "30mm",
      right: "20mm",
      bottom: "25mm",
      left: "20mm",
    },
  });

  await browser.close();
  return Buffer.from(pdf);
}
