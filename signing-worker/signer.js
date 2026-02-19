import { plainAddPlaceholder } from "@signpdf/placeholder-plain";
import { SignPdf } from "@signpdf/signpdf";
import { Signer } from "@signpdf/utils"; // <--- Add this import
import { spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

// 1. Define a class that satisfies the library's strict check
class ExternalSigner extends Signer {
  constructor(signatureBuffer) {
    super();
    this.signatureBuffer = signatureBuffer;
  }

  // The library calls this method internally
  async sign() {
    return this.signatureBuffer;
  }
}

const SIGNATURE_LENGTH = 16384;

export async function signBuffer(pdfBuffer) {
  if (process.env.NODE_ENV === "development") {
    console.log("⚠️ Dev mode → skipping signing");
    return pdfBuffer;
  }

  console.log("🚀 Starting production-grade PDF signing...");

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
    console.log("🔐 Creating PKCS#7 CMS signature via OpenSSL + PKCS#11...");

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
        env: { ...process.env }, 
        encoding: null, 
        maxBuffer: 20 * 1024 * 1024 
      }
    );

    if (opensslSign.status !== 0) {
      throw new Error(`OpenSSL failed: ${opensslSign.stderr?.toString()}`);
    }

    const cmsSignature = fs.readFileSync(cmsFile);
    console.log("✅ PKCS#7 CMS signature created");

    // 3️⃣ Inject CMS into PDF using the Class-based Signer
    const signPdf = new SignPdf();
    
    // Create an instance of our custom class so 'instanceof Signer' is true
    const signerInstance = new ExternalSigner(cmsSignature);

    // Call sign (it is an async method in their source code)
    const signedPdfBuffer = await signPdf.sign(pdfWithPlaceholder, signerInstance);

    console.log("🎉 PDF successfully signed (PKCS#7 style via PKCS#11)");

    return signedPdfBuffer;
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (err) {
      console.warn("⚠️ Temp cleanup failed:", err);
    }
  }
}