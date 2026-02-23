import { plainAddPlaceholder } from "@signpdf/placeholder-plain";
import { SignPdf } from "@signpdf/signpdf";
import { Signer } from "@signpdf/utils";
import { spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

const SIGNATURE_LENGTH = 1500000;
class ExternalSigner extends Signer {
  async sign(bufferToSign) {
    console.log("🚀 Starting production-grade PAdES signing...");

    const certPath = process.env.CERT_FILE;
    const chainPath = process.env.INTERMEDIATE_CERT; 

    // Path Validation
    if (!fs.existsSync(certPath)) throw new Error(`❌ Missing CERT_FILE: ${certPath}`);
    if (!fs.existsSync(chainPath)) {
        console.warn(`⚠️ Warning: full-chain.pem not found at ${chainPath}. Adobe might show trust errors.`);
    }

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sign-"));
    const dataPath = path.join(tmpDir, "data.bin");
    const cmsPath = path.join(tmpDir, "sig.der");
    const tsQueryPath = path.join(tmpDir, "tsq.der");
    const tsRespPath = path.join(tmpDir, "tsr.der");

    fs.writeFileSync(dataPath, bufferToSign);

    try {
      const openssl = process.env.OPENSSL_BIN;

      // 1️⃣ Generate CMS signature using the Token + Full Chain
      console.log("🔐 Generating CMS signature via Hardware Token...");
      const signArgs = [
        "cms", "-sign", "-binary",
        "-in", dataPath,
        "-signer", certPath,
        "-engine", "pkcs11",
        "-keyform", "engine",
        "-inkey", `pkcs11:token=${process.env.PKCS11_TOKEN_LABEL};type=private;pin-value=${process.env.PKCS11_PIN}`,
        "-outform", "DER",
        "-md", "sha256",
        "-nosmimecap", // FIX: Removes S/MIME attributes that cause "Suspicious Data" errors
        "-nodetach",
        "-out", cmsPath,
      ];

      // Inject the verified chain (Intermediate + Root) into the signature
      if (chainPath && fs.existsSync(chainPath)) {
        signArgs.push("-certfile", chainPath);
      }

      const sign = spawnSync(openssl, signArgs, {
        encoding: null,
        env: {
          ...process.env,
          PKCS11_MODULE_PATH: process.env.PKCS11_MODULE 
        },
      });

      if (sign.status !== 0) {
        console.error("❌ OpenSSL CMS Error:", sign.stderr?.toString());
        throw new Error("OpenSSL CMS command failed. Check token connection and PIN.");
      }

      // 2️⃣ Create RFC3161 Timestamp Query
      console.log("⏳ Requesting RFC3161 timestamp...");
      const tsArgs = ["ts", "-query", "-data", cmsPath, "-sha256", "-cert", "-out", tsQueryPath];
      spawnSync(openssl, tsArgs, { env: process.env });

      // 3️⃣ Fetch Timestamp Response from Sectigo
      const curlResponse = spawnSync("curl", [
        "-s", "-H", "Content-Type: application/timestamp-query",
        "--data-binary", `@${tsQueryPath}`,
        process.env.TSA_URL,
        "-o", tsRespPath
      ]);

      if (!fs.existsSync(tsRespPath) || fs.statSync(tsRespPath).size === 0) {
        throw new Error("Failed to receive timestamp response from TSA.");
      }

      // 4️⃣ Inject Timestamp Token into CMS Unsigned Attributes
      const cmsBuffer = fs.readFileSync(cmsPath);
      const tsrBuffer = fs.readFileSync(tsRespPath);
      const signedDataBuffer = this.injectTimestamp(cmsBuffer, tsrBuffer);
      
      console.log(`✅ Signature Complete: ${signedDataBuffer.length} bytes`);
      return signedDataBuffer;

    } finally {
      // Clean up temporary files
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  injectTimestamp(cmsBuffer, tsrBuffer) {
    
    const cmsArrayBuffer = cmsBuffer.buffer.slice(cmsBuffer.byteOffset, cmsBuffer.byteOffset + cmsBuffer.byteLength);
    const tsrArrayBuffer = tsrBuffer.buffer.slice(tsrBuffer.byteOffset, tsrBuffer.byteOffset + tsrBuffer.byteLength);

    const asn1 = asn1js.fromBER(cmsArrayBuffer);
    const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
    const signedData = new pkijs.SignedData({ schema: contentInfo.content });

    const tsrAsn1 = asn1js.fromBER(tsrArrayBuffer);
    const tsrInfo = new pkijs.TimeStampResp({ schema: tsrAsn1.result });

    const signer = signedData.signerInfos[0];
    if (!tsrInfo.timeStampToken) {
  throw new Error("TSA response does not contain a timeStampToken.");
}
    // Initialize unsigned attributes if they don't exist
    if (!signer.unsignedAttributes) {
        signer.unsignedAttributes = new pkijs.SignedAndUnsignedAttributes({
            type: 1, 
            attributes: []
        });
    }

    // Add the timestamp token attribute (OID: 1.2.840.113549.1.9.16.2.14)
    signer.unsignedAttributes.attributes.push(new pkijs.Attribute({
      type: "1.2.840.113549.1.9.16.2.14",
      values: [tsrInfo.timeStampToken.toSchema()]
    }));

    const finalContentInfo = new pkijs.ContentInfo({
      contentType: "1.2.840.113549.1.7.2",
      content: signedData.toSchema()
    });

    // Use Definite Length Encoding for strict Adobe Parser compatibility
    return Buffer.from(finalContentInfo.toSchema().toBER(true));
  }
}

export async function signBuffer(pdfBuffer) {
  if (process.env.NODE_ENV === "development") {
    console.log("⚠️ Development mode: Skipping hardware signature.");
    return pdfBuffer;
  }
  
  const pdfWithPlaceholder = plainAddPlaceholder({
    pdfBuffer,
    reason: "TransferGuard Legal Seal",
    signatureLength: SIGNATURE_LENGTH,
  });

  return await new SignPdf().sign(pdfWithPlaceholder, new ExternalSigner());
}