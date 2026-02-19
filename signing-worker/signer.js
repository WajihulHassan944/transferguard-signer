import { plainAddPlaceholder } from "@signpdf/placeholder-plain";
import { SignPdf } from "@signpdf/signpdf";
import { spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

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

  // 2️⃣ Prepare temp file for input only
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sign-"));
  const inputPdf = path.join(tmpDir, "input.pdf");

  fs.writeFileSync(inputPdf, pdfWithPlaceholder);

  const opensslEnv = {
    ...process.env,
    PKCS11_MODULE: process.env.PKCS11_MODULE,
    PIN: process.env.PKCS11_PIN,
    OPENSSL_CONF: process.env.OPENSSL_CONF,
  };

  try {
    console.log("🔐 Creating PKCS#7 CMS signature...");

    const opensslSign = spawnSync(
      "openssl",
      [
        "cms",
        "-sign",
        "-binary",
        "-in",
        inputPdf,
        "-signer",
        process.env.CERT_FILE,
        "-certfile",
        process.env.INTERMEDIATE_CERT,
        "-engine",
        "pkcs11",
        "-keyform",
        "engine",
        "-inkey",
        `pkcs11:token=${process.env.PKCS11_TOKEN_LABEL};id=${process.env.PKCS11_KEY_ID};type=private`,
        "-outform",
        "DER",
        "-md",
        "sha256",
        "-nodetach",
      ],
      {
        env: opensslEnv,
        encoding: null, // 👈 VERY IMPORTANT (returns Buffer)
        maxBuffer: 10 * 1024 * 1024,
      }
    );

    if (opensslSign.status !== 0) {
      throw new Error(
        `OpenSSL signing failed:\n${
          opensslSign.stderr?.toString() ||
          opensslSign.stdout?.toString() ||
          "Unknown error"
        }`
      );
    }

    if (!opensslSign.stdout || opensslSign.stdout.length === 0) {
      throw new Error("OpenSSL did not return CMS signature data");
    }

    console.log("✅ PKCS#7 CMS signature created");

    const cmsSignature = opensslSign.stdout;

    // 4️⃣ Inject CMS into PDF
    const signPdf = new SignPdf();
    const signedPdfBuffer = signPdf.sign(pdfWithPlaceholder, {
      sign: () => cmsSignature,
    });

    console.log("🎉 PDF successfully signed (PKCS#7, no TSA)");

    return signedPdfBuffer;
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (err) {
      console.warn("⚠️ Failed to remove temp files:", err);
    }
  }
}
