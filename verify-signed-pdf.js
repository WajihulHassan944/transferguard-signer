import fs from "fs";
import path from "path";
import { PDFDocument } from "pdf-lib";
import forge from "node-forge";

// Path to your signed PDF
const pdfPath = path.resolve(
  decodeURIComponent("C:/Users/whassan.bee-57mcs/Downloads/signed-audit_b6b9d734-baed-4b38-b75d-841545e5c401%20(6).pdf")
);

async function verifyPdf() {
  try {
    const pdfBuffer = fs.readFileSync(pdfPath);
    const pdfDoc = await PDFDocument.load(pdfBuffer);

    // Get the signature field
    const signatureFields = pdfDoc.getForm().getFields();

    if (signatureFields.length === 0) {
      console.error("❌ No signature fields found in the PDF.");
      return;
    }

    console.log("✅ Found signature fields:", signatureFields);

    // Assume we're extracting the first signature field
    const signatureField = signatureFields[0];
    const signatureData = signatureField.acroField.getValue(); // Extract the signature
    const signedData = pdfBuffer; // You may need to extract the exact data that was signed from the document

    // Public Key for signature verification (you need to have the correct public key)
    const publicKeyPem = `-----BEGIN PUBLIC KEY-----
YOUR_PUBLIC_KEY_HERE
-----END PUBLIC KEY-----`;

    const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);

    // Verify the signature (signatureData) against the data (signedData)
    const isValid = publicKey.verify(signedData, signatureData, 'sha256');
    if (isValid) {
      console.log("✅ PDF signature is valid!");
    } else {
      console.error("❌ PDF signature is invalid!");
    }
  } catch (err) {
    console.error("❌ PDF verification failed:", err.message);
  }
}

verifyPdf();
