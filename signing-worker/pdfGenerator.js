import puppeteer from "puppeteer";
import fs from "fs";
import path from "path";

export async function generatePDF(data) {
  const templatePath = path.resolve("signing-worker/email.html");
  let html = fs.readFileSync(templatePath, "utf8");

  // --------------------------------------------------
  // Browser / OS Detection
  // --------------------------------------------------
  const getBrowserName = (ua = "") => {
    if (ua.includes("Edg")) return "Microsoft Edge";
    if (ua.includes("Chrome")) return "Google Chrome";
    if (ua.includes("Firefox")) return "Mozilla Firefox";
    if (ua.includes("Safari") && !ua.includes("Chrome")) return "Safari";
    return "Web Browser";
  };

  const getOSName = (ua = "") => {
    if (ua.includes("Windows NT 10")) return "Windows 10";
    if (ua.includes("Windows NT 11")) return "Windows 11";
    if (ua.includes("Mac OS X")) return "macOS";
    if (ua.includes("Android")) return "Android";
    if (ua.includes("iPhone")) return "iOS";
    return "Desktop";
  };

  const cleanBrowser = getBrowserName(data.browser);
  const cleanOS = getOSName(data.browser);

  // --------------------------------------------------
  // Helpers
  // --------------------------------------------------
  const escape = (v) =>
    String(v ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;");

  const formatDate = (d) => {
    if (!d) return "";
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
  };

  const formatFileSize = (bytes) => {
    if (!bytes) return "";
    const tb = bytes / 1024 ** 4;
    const gb = bytes / 1024 ** 3;
    const mb = bytes / 1024 ** 2;
    if (tb >= 1) return tb.toFixed(2) + " TB";
    if (gb >= 1) return gb.toFixed(2) + " GB";
    return mb.toFixed(2) + " MB";
  };

  // ==================================================
  // VERIFICATION METHOD BLOCKS (MASTER ALIGNED)
  // ==================================================

let verificationBlock = "";

if (data.verification_method === "email") {
  verificationBlock = `
    <h2>4. Email Verification</h2>

    <div class="row">
      <div class="label">Verified Email:</div>
      <div class="value">${escape(data.recipient_email)}</div>
    </div>

    <div class="row">
      <div class="label">Verification Timestamp:</div>
      <div class="value">${formatDate(data.verification_timestamp)}</div>
    </div>

    <div class="row">
      <div class="label">Unique Token ID:</div>
      <div class="value mono">${escape(data.unique_token_id)}</div>
    </div>

    <div class="intro">
      Recipient identity was confirmed via a One-Time Password (OTP)
      sent to the registered email address.
    </div>
  `;
}

if (data.verification_method === "sms") {
  verificationBlock = `
    <h2>4. SMS Verification</h2>

    <div class="row">
      <div class="label">Telephone Number:</div>
      <div class="value">${escape(data.telephone_number)}</div>
    </div>

    <div class="row">
      <div class="label">Verification Timestamp:</div>
      <div class="value">${formatDate(data.verification_timestamp)}</div>
    </div>

    <div class="row">
      <div class="label">Unique Token ID:</div>
      <div class="value mono">${escape(data.unique_token_id)}</div>
    </div>

    <div class="intro">
      Recipient identity was confirmed via a One-Time Password (OTP)
      sent to the registered telephone number via SMS.
    </div>
  `;
}

if (data.verification_method === "email_sms") {
  verificationBlock = `
    <h2>4. Multi-Factor Authentication (MFA)</h2>

    <div class="row">
      <div class="label">Email Address:</div>
      <div class="value">${escape(data.recipient_email)}</div>
    </div>
 <div class="row">
    <div class="label">Email Verified At:</div>
<div class="value">${formatDate(data.email_verified_at)}</div>
    </div>
    <div class="row">
      <div class="label">Telephone Number:</div>
      <div class="value">${escape(data.telephone_number)}</div>
    </div>

    <div class="row">
     <div class="label">SMS Verified At:</div>
<div class="value">${formatDate(data.sms_verified_at)}</div>
    </div>

    <div class="row">
      <div class="label">Unique Token ID:</div>
      <div class="value mono">${escape(data.unique_token_id)}</div>
    </div>

    <div class="intro">
      Identity was confirmed through Multi-Factor Authentication (MFA),
      requiring independent validation via OTP sent to both email and SMS.
    </div>
  `;
}

if (data.verification_method === "id_verification") {
  verificationBlock = `
    <h2>4. Recipient Identity Verification</h2>

    <div class="row">
      <div class="label">Full Name (ID):</div>
      <div class="value">${escape(data.recipient_name)}</div>
    </div>

    <div class="row">
      <div class="label">ID Document Type:</div>
      <div class="value">${escape(data.id_type)}</div>
    </div>

    <div class="row">
      <div class="label">Document Number (Last 4):</div>
      <div class="value">${escape(data.last_digits_iddocument)}</div>
    </div>

    <div class="row">
      <div class="label">Biometric Match:</div>
      <div class="value">${escape(data.biometric_match)}</div>
    </div>

    <div class="row">
      <div class="label">Verification Timestamp:</div>
      <div class="value">${formatDate(data.external_timestamp)}</div>
    </div>

    <div class="intro">
      Identity was established through biometric facial verification
      and validation of a government-issued identification document.
    </div>
  `;
}
  // ==================================================
  // LEGAL ACTION SECTION (e0 / e1 EXACT MATCH)
  // ==================================================

  let legalActionBlock = "";

  if (data.agreement_type === "one_click") {
    legalActionBlock = `
      <h2>5. Electronic Consent & Receipt Acknowledgment</h2>
      <p>
        The recipient has electronically acknowledged receipt of the files and 
        accepted the Terms of Service via a secure one-click agreement.
      </p>
      <p>
        Explicit digital consent granted at ${formatDate(data.signature_date)} 
        from IP ${escape(data.ip_address)}.
      </p>
    `;
  }

  if (data.agreement_type === "signature") {
    legalActionBlock = `
      <h2>5. Recipient Digital Signature</h2>
      <p>"I hereby acknowledge the receipt of the files mentioned in Section 1 in good order."</p>
      <div class="signature-box">
        <img src="${escape(data.signature_url || "")}" 
             style="max-height:120px;" 
             onerror="this.style.display='none'" />
      </div>
      <div>
        Signature name: ${escape(data.signature_name || data.recipient_name)}<br/>
        Date: ${formatDate(data.signature_date)}
      </div>
    `;
  }

  // ==================================================
  // TEMPLATE REPLACEMENTS
  // ==================================================

  html = html
    .replaceAll("{{PLAN_NAME}}", escape(data.plan_name))
    .replaceAll("{{AUDIT_ID}}", escape(data.audit_id))

    .replaceAll("{{name_organisation_sender}}", escape(data.sender_org))
    .replaceAll("{{sender_name}}", escape(data.sender_name))
    .replaceAll("{{sender_email}}", escape(data.sender_email))
    .replaceAll("{{verified_domain}}", escape(data.verified_domain))

 .replaceAll("{{recipient_name}}", escape(data.recipient_name))
    .replaceAll("{{recipient_email}}", escape(data.recipient_email))

    .replaceAll("{{name_organisation_receiver}}", escape(data.recipient_name))
    .replaceAll("{{TIME_DATE_SEND}}", formatDate(data.verification_timestamp))
    .replaceAll("{{TIME_DATE_RECEIVED}}", formatDate(data.verification_timestamp))

    .replaceAll("{{FiLE_NAME}}", escape(data.file_name))
    .replaceAll("{{HASH}}", escape(data.sha256_hash))
    .replaceAll("{{FILE_SIZE}}", formatFileSize(data.file_size_bytes))
    .replaceAll("{{choosen_verification}}", escape(data.verification_method))

    .replaceAll("{{IP_ADDRESS}}", escape(data.ip_address))
    .replaceAll("{{LOCATION}}", escape(data.location))
    .replaceAll("{{DEVICE_OS}}", escape(cleanOS))
    .replaceAll("{{BROWSER}}", escape(cleanBrowser))

    .replaceAll("{{TSA_PROVIDER}}", escape(data.tsa_provider))
    .replaceAll("{{ENCRYPTION_STANDARD}}", escape(data.encryption_standard))
    .replaceAll("{{TERMS_VERSION}}", escape(data.terms_version))
    .replaceAll("{{PRIVACY_VERSION}}", escape(data.privacy_version))

    .replaceAll("{{VERIFICATION_BLOCK}}", verificationBlock)
    .replaceAll("{{LEGAL_ACTION_BLOCK}}", legalActionBlock);

  // ==================================================
  // GENERATE PDF
  // ==================================================

  const browser = await puppeteer.launch({
    headless: "new",
    args: ["--no-sandbox"],
  });

  const page = await browser.newPage();
  await page.setContent(html, { waitUntil: "networkidle0" });

  // --------------------------------------------------
// Dynamic Footer Text (Professional Version)
// --------------------------------------------------

let verificationLabel = "";
let actionLabel = "";

switch (data.verification_method) {
  case "email":
    verificationLabel = "Email OTP Verification";
    break;
  case "sms":
    verificationLabel = "SMS OTP Verification";
    break;
  case "email_sms":
    verificationLabel = "Multi-Factor Authentication (Email + SMS OTP)";
    break;
  case "id_verification":
    verificationLabel = "Biometric ID Verification";
    break;
  default:
    verificationLabel = "Digital Verification";
}

switch (data.agreement_type) {
  case "one_click":
    actionLabel = "Secure One-Click Electronic Consent";
    break;
  case "signature":
    actionLabel = "Digitally Captured Signature";
    break;
  default:
    actionLabel = "Electronic Legal Acknowledgment";
}

const dynamicFooterIntro = `
  This "Certificate of Evidence" confirms completion of ${verificationLabel}
  and ${actionLabel}. The document is cryptographically sealed via the 
  TransferGuard Legal Engine (PDF Signing) to ensure integrity and court-admissibility.
`;

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
    <center>
      <div style="font-family: 'Inter', Arial; font-size: 12px; width: 70%; text-align: center; color: #444; padding: 0 20px;">
        
        <div style="margin-bottom: 6px;">
          ${dynamicFooterIntro}
        </div>

        <div style="margin-bottom: 4px;">
         TransferGuard ${escape(data.plan_name)} - Audit ID: ${escape(data.audit_id)} - Page 
          <span class="pageNumber"></span>
        </div>

        <div>
          TransferGuard is part of PVG Technologies BV, The Netherlands
        </div>

      </div>
    </center>
  `,
  preferCSSPageSize: false,
});


  await browser.close();
  return Buffer.from(pdf);
}