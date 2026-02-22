import { plainAddPlaceholder } from "@signpdf/placeholder-plain";
import { SignPdf } from "@signpdf/signpdf";
import { Signer } from "@signpdf/utils";
import { spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

const SIGNATURE_LENGTH = 32768;

class ExternalSigner extends Signer {
  async sign(bufferToSign) {
    console.log("🚀 Starting production-grade PDF signing...");

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sign-"));
    const dataPath = path.join(tmpDir, "data.bin");
    const cmsPath = path.join(tmpDir, "sig.der");
    const tsQueryPath = path.join(tmpDir, "tsq.der");
    const tsRespPath = path.join(tmpDir, "tsr.der");

    fs.writeFileSync(dataPath, bufferToSign);

    try {
      const openssl = process.env.OPENSSL_BIN || "/opt/homebrew/opt/openssl@3/bin/openssl";

      // 1️⃣ Create CMS signature
      // We pass environment variables explicitly so the PKCS11 engine knows where to look
      console.log("🔐 Generating CMS signature via Hardware Token...");
      const signArgs = [
        "cms", "-sign", "-binary",
        "-in", dataPath,
        "-signer", process.env.CERT_FILE,
        "-certfile", process.env.INTERMEDIATE_CERT,
        "-engine", "pkcs11",
        "-keyform", "engine",
        "-inkey", `pkcs11:token=${process.env.PKCS11_TOKEN_LABEL};type=private;pin-value=${process.env.PKCS11_PIN}`,
        "-outform", "DER",
        "-sha256",
        "-out", cmsPath,
      ];

      const sign = spawnSync(openssl, signArgs, {
        encoding: null,
        env: {
          ...process.env,
          OPENSSL_CONF: process.env.OPENSSL_CONF,
          // This is critical: The engine needs to know which module to use for the token
          PKCS11_MODULE_PATH: process.env.PKCS11_MODULE 
        },
      });

      if (sign.status !== 0 || !fs.existsSync(cmsPath)) {
        console.error("❌ OpenSSL CMS Error Details:");
        console.error(sign.stderr?.toString());
        throw new Error(`OpenSSL failed to create CMS: ${sign.stderr?.toString()}`);
      }

      // 2️⃣ Create RFC3161 Timestamp Query
      console.log("⏳ Requesting RFC3161 timestamp from Sectigo...");
      const tsArgs = [
        "ts", "-query",
        "-data", cmsPath,
        "-sha256",
        "-cert",
        "-out", tsQueryPath
      ];
      
      const query = spawnSync(openssl, tsArgs, {
        env: { ...process.env, OPENSSL_CONF: process.env.OPENSSL_CONF }
      });

      if (query.status !== 0 || !fs.existsSync(tsQueryPath)) {
        throw new Error(`TS Query failed: ${query.stderr?.toString()}`);
      }

      // 3️⃣ Fetch Timestamp Response from Sectigo
      const curl = spawnSync("curl", [
        "-s", "-H", "Content-Type: application/timestamp-query",
        "--data-binary", `@${tsQueryPath}`,
        "http://timestamp.sectigo.com",
        "-o", tsRespPath
      ]);

      if (!fs.existsSync(tsRespPath) || fs.statSync(tsRespPath).size === 0) {
        throw new Error("Failed to receive valid timestamp response from Sectigo");
      }

      // 4️⃣ Inject Timestamp Token into CMS using Node ASN.1 (pkijs)
      const cmsBuffer = fs.readFileSync(cmsPath);
      const tsrBuffer = fs.readFileSync(tsRespPath);

      const signedData = this.injectTimestamp(cmsBuffer, tsrBuffer);
      
      console.log(`✅ CMS signature with injected timestamp created (${signedData.length} bytes)`);
      return Buffer.from(signedData);

    } finally {
      // Cleanup temp files
      try {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      } catch (err) {
        console.error("⚠️ Temp cleanup error:", err);
      }
    }
  }

  injectTimestamp(cmsBuffer, tsrBuffer) {
    const cmsArrayBuffer = cmsBuffer.buffer.slice(cmsBuffer.byteOffset, cmsBuffer.byteOffset + cmsBuffer.byteLength);
    const tsrArrayBuffer = tsrBuffer.buffer.slice(tsrBuffer.byteOffset, tsrBuffer.byteOffset + tsrBuffer.byteLength);

    const asn1 = asn1js.fromBER(cmsArrayBuffer);
    if (asn1.offset === -1) throw new Error("Failed to parse CMS ASN.1");
    
    const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
    const signedData = new pkijs.SignedData({ schema: contentInfo.content });

    const tsrAsn1 = asn1js.fromBER(tsrArrayBuffer);
    if (tsrAsn1.offset === -1) throw new Error("Failed to parse TSR ASN.1");
    
    const tsrInfo = new pkijs.TimeStampResp({ schema: tsrAsn1.result });
    if (!tsrInfo.timeStampToken) throw new Error("Timestamp response missing token");

    const signer = signedData.signerInfos[0];
    signer.unsignedAttributes = signer.unsignedAttributes || new pkijs.SignedAndUnsignedAttributes({ type: 1 });
    
    signer.unsignedAttributes.attributes.push(new pkijs.Attribute({
      type: "1.2.840.113549.1.9.16.2.14", // id-aa-timeStampToken
      values: [tsrInfo.timeStampToken.toSchema()]
    }));

    return signedData.toContentInfo().toBER(false);
  }
}

export async function signBuffer(pdfBuffer) {
  if (process.env.NODE_ENV === "development") {
    console.log("⚠️ Dev mode → skipping signing");
    return pdfBuffer;
  }

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