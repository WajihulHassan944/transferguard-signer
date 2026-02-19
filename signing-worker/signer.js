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

  // 2️⃣ Prepare temp files
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sign-"));
  const inputPdf = path.join(tmpDir, "input.pdf");
  const cmsFile = path.join(tmpDir, "signature.p7s");

  fs.writeFileSync(inputPdf, pdfWithPlaceholder);

  const opensslEnv = {
    ...process.env,
    PKCS11_MODULE: process.env.PKCS11_MODULE,
    PKCS11_PIN: process.env.PKCS11_PIN,
    OPENSSL_CONF: process.env.OPENSSL_CONF,
  };

  try {
    console.log("🔐 Creating PKCS#7 CMS signature via OpenSSL + PKCS#11...");

// Change the spawnSync call to use your environment variable path
const opensslSign = spawnSync(
  process.env.OPENSSL_BIN, // This uses /opt/homebrew/opt/openssl@3/bin/openssl
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
    `pkcs11:token=${process.env.PKCS11_TOKEN_LABEL};id=${process.env.PKCS11_KEY_ID};type=private;pin-value=${process.env.PKCS11_PIN}`,
    "-outform",
    "DER",
    "-md",
    "sha256",
    "-nodetach",
    "-out",
    cmsFile,
  ],
  { 
    env: opensslEnv, 
    encoding: null, 
    maxBuffer: 20 * 1024 * 1024 
  }
);

    if (opensslSign.status !== 0) {
      throw new Error(
        `OpenSSL CMS signing failed:\n${
          opensslSign.stderr?.toString() || opensslSign.stdout?.toString() || "Unknown error"
        }`
      );
    }

    const cmsSignature = fs.readFileSync(cmsFile);

    console.log("✅ PKCS#7 CMS signature created");

    // 3️⃣ Inject CMS into PDF
    const signPdf = new SignPdf();
    const signedPdfBuffer = signPdf.sign(pdfWithPlaceholder, {
      sign: () => cmsSignature,
    });

    console.log("🎉 PDF successfully signed (PKCS#7 style via PKCS#11)");

    return signedPdfBuffer;
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (err) {
      console.warn("⚠️ Failed to remove temp files:", err);
    }
  }
}
