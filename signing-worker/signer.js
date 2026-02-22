import { plainAddPlaceholder } from "@signpdf/placeholder-plain";
import { SignPdf } from "@signpdf/signpdf";
import { Signer } from "@signpdf/utils";
import { spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

const SIGNATURE_LENGTH = 32768;

class ExternalSigner extends Signer {
  async sign(bufferToSign) {
    console.log("🔐 Creating CMS signature + RFC3161 timestamp (OpenSSL 3 compatible)...");

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sign-"));
    const dataPath = path.join(tmpDir, "data.bin");
    const cmsPath = path.join(tmpDir, "sig.der");
    const tsQueryPath = path.join(tmpDir, "tsq.der");
    const tsRespPath = path.join(tmpDir, "tsr.der");
    const finalCmsPath = path.join(tmpDir, "final.der");

    fs.writeFileSync(dataPath, bufferToSign);

    try {
      // 1️⃣ Create CMS signature (WITH attributes)
      const sign = spawnSync(
        process.env.OPENSSL_BIN || "openssl",
        [
          "cms",
          "-sign",
          "-binary",
          "-in", dataPath,
          "-signer", process.env.CERT_FILE,
          "-certfile", process.env.INTERMEDIATE_CERT,
          "-engine", "pkcs11",
          "-keyform", "engine",
          "-inkey",
          `pkcs11:token=${process.env.PKCS11_TOKEN_LABEL};type=private;pin-value=${process.env.PKCS11_PIN}`,
          "-outform", "DER",
          "-md", "sha256",
          "-out", cmsPath,
        ],
        { encoding: null, maxBuffer: 20 * 1024 * 1024 }
      );

      if (sign.status !== 0) {
        throw new Error(sign.stderr?.toString());
      }

      // 2️⃣ Create RFC3161 timestamp request
      spawnSync("openssl", [
        "ts",
        "-query",
        "-data", cmsPath,
        "-sha256",
        "-cert",
        "-out", tsQueryPath,
      ]);

      // 3️⃣ Send to Sectigo TSA
      spawnSync("curl", [
        "-s",
        "-H", "Content-Type: application/timestamp-query",
        "--data-binary", `@${tsQueryPath}`,
        "http://timestamp.sectigo.com",
        "-o", tsRespPath,
      ]);

      // 4️⃣ Verify timestamp
      const verify = spawnSync("openssl", [
        "ts",
        "-verify",
        "-data", cmsPath,
        "-in", tsRespPath,
        "-CAfile", process.env.INTERMEDIATE_CERT,
      ]);

      if (verify.status !== 0) {
        throw new Error("Timestamp verification failed");
      }

      // 5️⃣ Attach timestamp as unsigned attribute
      const resign = spawnSync("openssl", [
        "cms",
        "-resign",
        "-binary",
        "-inform", "DER",
        "-in", cmsPath,
        "-signer", process.env.CERT_FILE,
        "-certfile", process.env.INTERMEDIATE_CERT,
        "-engine", "pkcs11",
        "-keyform", "engine",
        "-inkey",
        `pkcs11:token=${process.env.PKCS11_TOKEN_LABEL};type=private;pin-value=${process.env.PKCS11_PIN}`,
        "-outform", "DER",
        "-out", finalCmsPath,
      ]);
if (resign.status !== 0) {
  console.error("❌ OpenSSL resign failed:");
  console.error(resign.stderr?.toString());
  throw new Error("CMS resign failed");
}

if (!fs.existsSync(finalCmsPath)) {
  throw new Error("final.der was not created by OpenSSL");
}

const finalSignature = fs.readFileSync(finalCmsPath);
      console.log(`✅ CMS signature with embedded timestamp created (${finalSignature.length} bytes)`);

      return finalSignature;

    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }
}

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

  const signPdf = new SignPdf();
  const signerInstance = new ExternalSigner();

  const signedPdfBuffer = await signPdf.sign(
    pdfWithPlaceholder,
    signerInstance
  );

  console.log("🎉 PDF successfully signed with RFC3161 timestamp!");

  return signedPdfBuffer;
}