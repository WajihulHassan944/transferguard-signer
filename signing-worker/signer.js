import { plainAddPlaceholder } from "@signpdf/placeholder-plain";
import { SignPdf } from "@signpdf/signpdf";
import { Signer } from "@signpdf/utils";
import { spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

const SIGNATURE_LENGTH = 32768; 

class ExternalSigner extends Signer {
  /**
   * bufferToSign is provided by @signpdf. 
   * It contains the exact bytes of the PDF defined by the ByteRange.
   */
  async sign(bufferToSign) {
    console.log("🔐 Creating Detached PKCS#7 CMS signature over correct ByteRange...");
    
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sign-"));
    const dataToSignPath = path.join(tmpDir, "data-to-sign.bin");
    const cmsFile = path.join(tmpDir, "signature.p7s");

    // 1. Save the specific bytes that @signpdf says need to be signed
    fs.writeFileSync(dataToSignPath, bufferToSign);

    try {
      // 2. OpenSSL signs ONLY those bytes
      const opensslSign = spawnSync(
        process.env.OPENSSL_BIN || "/opt/homebrew/opt/openssl@3/bin/openssl",
        [
          "cms",
          "-sign",
          "-binary",
          "-in", dataToSignPath, 
          "-signer", process.env.CERT_FILE,
          "-certfile", process.env.INTERMEDIATE_CERT,
          "-engine", "pkcs11",
          "-keyform", "engine",
          "-inkey", `pkcs11:token=${process.env.PKCS11_TOKEN_LABEL};type=private;pin-value=${process.env.PKCS11_PIN}`,
          "-outform", "DER",
          "-md", "sha256",
          "-nosmimecap",  
          // Note: If Adobe still complains, we will remove "-noattr" next.
          "-noattr",
          "-out", cmsFile,
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

      // 3. Return the signature back to @signpdf to be injected into the PDF
      const cmsSignature = fs.readFileSync(cmsFile);
      console.log(`✅ Detached CMS signature created (${cmsSignature.length} bytes)`);
      return cmsSignature;
      
    } finally {
      // Clean up temp files immediately
      try {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      } catch (err) {
        console.warn("⚠️ Temp cleanup failed:", err);
      }
    }
  }
}

export async function signBuffer(pdfBuffer) {
  if (process.env.NODE_ENV === "development") {
    console.log("⚠️ Dev mode → skipping signing");
    return pdfBuffer;
  }

  console.log("🚀 Starting production-grade PDF signing...");

  // A. Add the placeholder
  const pdfWithPlaceholder = plainAddPlaceholder({
    pdfBuffer,
    reason: "TransferGuard Legal Seal",
    signatureLength: SIGNATURE_LENGTH,
  });

  // B. Trigger the internal signing process
  const signPdf = new SignPdf();
  const signerInstance = new ExternalSigner();

  // The .sign method now calls our ExternalSigner.sign() internally with the correct bytes
  const signedPdfBuffer = await signPdf.sign(pdfWithPlaceholder, signerInstance);

  console.log("🎉 PDF successfully signed with correct ByteRange!");

  return signedPdfBuffer;
}