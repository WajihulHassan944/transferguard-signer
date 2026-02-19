import { plainAddPlaceholder } from "@signpdf/placeholder-plain";
import { SignPdf } from "@signpdf/signpdf";
import { spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import crypto from "crypto";

const SIGNATURE_LENGTH = 16384; // Enough for full cert chain

export async function signBuffer(pdfBuffer) {
  if (process.env.NODE_ENV === "development") {
    console.log("⚠️ Dev mode → skipping signing");
    return pdfBuffer;
  }

  console.log("🚀 Starting production-grade PDF signing...");

  // 1️⃣ Add placeholder
  const pdfWithPlaceholder = plainAddPlaceholder({
    pdfBuffer,
    reason: "TransferGuard Legal Seal",
    signatureLength: SIGNATURE_LENGTH,
  });

  console.log("✅ Placeholder added");

  // 2️⃣ Prepare temp files
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sign-"));
  const inputPdf = path.join(tmpDir, "input.pdf");
  const hashFile = path.join(tmpDir, "hash.bin");
  const sigFile = path.join(tmpDir, "sig.bin");

  fs.writeFileSync(inputPdf, pdfWithPlaceholder);

  try {
    // 3️⃣ Compute hash of PDF placeholder
    const hash = crypto.createHash("sha256").update(pdfWithPlaceholder).digest();
    fs.writeFileSync(hashFile, hash);

    console.log("🔐 Hash of PDF placeholder computed");

    // 4️⃣ Sign hash using PKCS#11 token
    const pkcs11Sign = spawnSync(
      "pkcs11-tool",
      [
        "--module",
        process.env.PKCS11_MODULE,
        "-l",
        "-p",
        process.env.PKCS11_PIN,
        "--sign",
        "--id",
        process.env.PKCS11_KEY_ID,
        "--input-file",
        hashFile,
        "--output-file",
        sigFile,
        "--mechanism",
        "RSA-PKCS",
      ],
      { encoding: "buffer" }
    );

    if (pkcs11Sign.status !== 0) {
      throw new Error(
        `PKCS#11 signing failed:\n${
          pkcs11Sign.stderr?.toString() || pkcs11Sign.stdout?.toString() || "Unknown error"
        }`
      );
    }

    console.log("✅ Hash signed via PKCS#11 token");

    const rawSignature = fs.readFileSync(sigFile);

    // 5️⃣ Inject raw signature into PDF
    const signPdf = new SignPdf();
    const signedPdfBuffer = signPdf.sign(pdfWithPlaceholder, {
      sign: () => rawSignature,
    });

    console.log("🎉 PDF successfully signed (PKCS#7 style via token)");

    return signedPdfBuffer;
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (err) {
      console.warn("⚠️ Failed to remove temp files:", err);
    }
  }
}
