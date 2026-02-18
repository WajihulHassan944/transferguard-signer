"use strict";

import fs from "fs";
import path from "path";

// ✅ Import CommonJS module correctly in ESM
import SignPdfPkg from "@signpdf/signpdf";
const { verify } = SignPdfPkg;

// Path to your signed PDF
const pdfPath = path.resolve(
  "C:/Users/whassan.bee-57mcs/Downloads/signed-audit_b6b9d734-baed-4b38-b75d-841545e5c401 (5).pdf"
);

async function verifyPdf() {
  try {
    const pdfBuffer = fs.readFileSync(pdfPath);

    // Use the verify function
    const info = verify(pdfBuffer);

    console.log("✅ PDF signature is valid!");
    console.log("Signature Info:", info);
  } catch (err) {
    console.error("❌ PDF verification failed:", err.message);
  }
}

verifyPdf();
