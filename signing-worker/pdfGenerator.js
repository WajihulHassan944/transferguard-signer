import puppeteer from "puppeteer";
import fs from "fs";
import path from "path";

export async function generatePDF(data) {
  const templatePath = path.resolve("signing-worker/template.html");
  let html = fs.readFileSync(templatePath, "utf8");

  const escape = (v = "") =>
    String(v)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;");

  const formatDate = (d = new Date()) =>
    new Date(d).toLocaleString("en-GB", { hour12: false }) + " CET";

  const fileRows = (data.files || [])
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
html = html
  .replaceAll("{{FILE_NAME}}", "Case_File_33492_Evidence.zip")
  .replaceAll("{{SHA256}}", data.sha256)
  .replaceAll("{{FILE_SIZE}}", data.fileSize)
  .replaceAll("{{TRANSFER_STATUS}}", "Successfully Downloaded & Identity Verified")

  .replaceAll("{{RECIPIENT_NAME}}", data.recipient.name)
  .replaceAll("{{ID_TYPE}}", data.recipient.idType)
  .replaceAll("{{ID_NUMBER}}", data.recipient.idNumber)
  .replaceAll("{{BIOMETRIC}}", data.recipient.biometric)
  .replaceAll("{{VERIFF_SESSION}}", data.recipient.veriffSession)
  .replaceAll("{{IDV_TIME}}", data.recipient.idvTime)

  .replaceAll("{{SIGNATURE_URL}}", data.signatureUrl)
  .replaceAll("{{SIGN_DATE}}", data.signDate)

  .replaceAll("{{IP}}", data.ip)
  .replaceAll("{{LOCATION}}", data.location)
  .replaceAll("{{DEVICE}}", data.device)
  .replaceAll("{{BROWSER}}", data.browser)

  .replaceAll("{{AUDIT_ID}}", "TG-20260204-LEGAL-X99");


  const browser = await puppeteer.launch({
    headless: "new",
    args: ["--no-sandbox", "--font-render-hinting=medium"]
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
      left: "20mm"
    }
  });

  await browser.close();
  return Buffer.from(pdf);
}
