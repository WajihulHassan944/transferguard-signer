import { plainAddPlaceholder } from "@signpdf/placeholder-plain";
import { SignPdf } from "@signpdf/signpdf";
import { Signer } from "@signpdf/utils";
import { spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

// 1. Increased length to 32k bytes (which is 64k hex chars) to be very safe
const SIGNATURE_LENGTH = 32768; 

class ExternalSigner extends Signer {
  constructor(signatureBuffer) {
    super();
    this.signatureBuffer = signatureBuffer;
  }
  async sign() {
    return this.signatureBuffer;
  }
}

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

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sign-"));
  const inputPdf = path.join(tmpDir, "input.pdf");
  const cmsFile = path.join(tmpDir, "signature.p7s");

  fs.writeFileSync(inputPdf, pdfWithPlaceholder);

  try {
    console.log("🔐 Creating Detached PKCS#7 CMS signature...");

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
        "-detached", // <--- CRITICAL CHANGE: Use detached instead of nodetach
        "-out",
        cmsFile,
      ],
      { 
        env: { ...process.env }, 
        encoding: null, 
        maxBuffer: 20 * 1024 * 1024 
      }
    );

    if (opensslSign.status !== 0) {
      throw new Error(`OpenSSL failed: ${opensslSign.stderr?.toString()}`);
    }

    const cmsSignature = fs.readFileSync(cmsFile);
    console.log(`✅ Detached CMS signature created (${cmsSignature.length} bytes)`);

    // 3️⃣ Inject CMS into PDF
    const signPdf = new SignPdf();
    const signerInstance = new ExternalSigner(cmsSignature);

    const signedPdfBuffer = await signPdf.sign(pdfWithPlaceholder, signerInstance);

    console.log("🎉 PDF successfully signed!");

    return signedPdfBuffer;
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (err) {
      console.warn("⚠️ Temp cleanup failed:", err);
    }
  }
}