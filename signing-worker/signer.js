import { plainAddPlaceholder } from "@signpdf/placeholder-plain";
import { SignPdf } from "@signpdf/signpdf";
import { spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

const TSA_URL = "http://timestamp.sectigo.com";
const SIGNATURE_LENGTH = 16384; // increase to accommodate cert chain + TSA token

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

  // 2️⃣ Temp files
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sign-"));
  const inputPdf = path.join(tmpDir, "input.pdf");
  const cmsFile = path.join(tmpDir, "signature.p7s");
  const tsQuery = path.join(tmpDir, "ts_query.tsq");
  const tsReply = path.join(tmpDir, "ts_reply.tsr");
  const finalPdf = path.join(tmpDir, "signed.pdf");

  fs.writeFileSync(inputPdf, pdfWithPlaceholder);

  try {
    // 3️⃣ Generate PKCS#7 signature using PKCS#11
    console.log("🔐 Creating PKCS#7 CMS signature...");

    const opensslSign = spawnSync("openssl", [
      "cms",
      "-sign",
      "-binary",
      "-in", inputPdf,
      "-signer", process.env.CERT_FILE,
      "-certfile", process.env.INTERMEDIATE_CERT,
      "-engine", "pkcs11",
      "-keyform", "engine",
      "-inkey", `pkcs11:token=${process.env.PKCS11_TOKEN_LABEL};id=${process.env.PKCS11_KEY_ID};type=private`,
      "-outform", "DER",
      "-out", cmsFile,
      "-md", "sha256",
      "-nodetach",
    ], {
      env: {
        ...process.env,
        PKCS11_MODULE: process.env.PKCS11_MODULE,
        PIN: process.env.PKCS11_PIN,
      }
    });

    if (opensslSign.status !== 0) {
      throw new Error(`OpenSSL signing failed:\n${opensslSign.stderr.toString() || opensslSign.stdout.toString()}`);
    }

    console.log("✅ PKCS#7 CMS signature created");

    // 4️⃣ Generate RFC3161 timestamp request
    console.log("🕒 Generating timestamp request...");
    spawnSync("openssl", [
      "ts",
      "-query",
      "-data", cmsFile,
      "-no_nonce",
      "-sha256",
      "-out", tsQuery
    ]);

    // 5️⃣ Send request to TSA
    const curlTSA = spawnSync("curl", [
      "-sS",
      "-H", "Content-Type: application/timestamp-query",
      "--data-binary", `@${tsQuery}`,
      TSA_URL,
      "-o", tsReply
    ]);

    if (curlTSA.status !== 0) {
      throw new Error("TSA request failed");
    }

    console.log("✅ TSA reply received");

    // 6️⃣ Embed TSA token into CMS (RFC3161)
    const timestampedCms = path.join(tmpDir, "timestamped.p7s");
    const tsEmbed = spawnSync("openssl", [
      "cms",
      "-in", cmsFile,
      "-out", timestampedCms,
      "-signer", process.env.CERT_FILE,
      "-certfile", process.env.INTERMEDIATE_CERT,
      "-engine", "pkcs11",
      "-keyform", "engine",
      "-inkey", `pkcs11:token=${process.env.PKCS11_TOKEN_LABEL};id=${process.env.PKCS11_KEY_ID};type=private`,
      "-outform", "DER",
      "-binary",
      "-attime", new Date().toISOString(), // optional
      "-tsacert", process.env.ROOT_CERT,
      "-tsareq", tsReply
    ]);

    if (tsEmbed.status !== 0) {
      throw new Error(`Embedding TSA token failed:\n${tsEmbed.stderr.toString() || tsEmbed.stdout.toString()}`);
    }

    console.log("✅ Timestamp embedded");

    // 7️⃣ Inject CMS into PDF
    const cmsSignature = fs.readFileSync(timestampedCms);
    const signPdf = new SignPdf();
    const signedPdfBuffer = signPdf.sign(pdfWithPlaceholder, {
      sign: () => cmsSignature
    });

    fs.writeFileSync(finalPdf, signedPdfBuffer);

    console.log("🎉 PDF fully signed with PKCS#7 + TSA");

    return signedPdfBuffer;
  } finally {
    // Clean up temp files
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (err) {
      console.warn("⚠️ Failed to remove temp files:", err);
    }
  }
}
