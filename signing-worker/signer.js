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

    // Using absolute path to Homebrew OpenSSL 3 to avoid macOS LibreSSL conflict
    // Using token-only URI to avoid the messy ID encoding issue
    const opensslSign = spawnSync(
      process.env.OPENSSL_BIN || "/opt/homebrew/opt/openssl@3/bin/openssl",
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
        `pkcs11:token=${process.env.PKCS11_TOKEN_LABEL};type=private;pin-value=${process.env.PKCS11_PIN}`,
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
    
    /**
     * FIX: The library expects a 'Signer' implementation.
     * Passing the signature directly as the second argument is the most 
     * reliable way to inject a pre-computed CMS block in recent versions.
     */
    const signedPdfBuffer = signPdf.sign(pdfWithPlaceholder, cmsSignature);

    console.log("🎉 PDF successfully signed (PKCS#7 style via PKCS#11)");

    return signedPdfBuffer;
  } finally {
    try {
      if (fs.existsSync(tmpDir)) {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    } catch (err) {
      console.warn("⚠️ Failed to remove temp files:", err);
    }
  }
}