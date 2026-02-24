import { plainAddPlaceholder } from "@signpdf/placeholder-plain";
import { SignPdf } from "@signpdf/signpdf";
import { Signer } from "@signpdf/utils";
import { spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

// 35KB is plenty for a detached signature with a full chain + TSA response.
const SIGNATURE_LENGTH = 35000;

class ExternalSigner extends Signer {
  async sign(bufferToSign) {
    console.log("🚀 Starting PAdES-compliant signing...");

    const certPath = process.env.CERT_FILE;
    const chainPath = process.env.INTERMEDIATE_CERT;

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sign-"));
    const dataPath = path.join(tmpDir, "data.bin");
    const cmsPath = path.join(tmpDir, "sig.der");

    fs.writeFileSync(dataPath, bufferToSign);

    try {
      const openssl = process.env.OPENSSL_BIN;

      // 1️⃣ Generate DETACHED CMS signature
      // Removing -nodetach fixes the massive file size issue.
      const signArgs = [
        "cms", "-sign", "-binary",
        "-in", dataPath,
        "-signer", certPath,
        "-engine", "pkcs11",
        "-keyform", "engine",
        "-inkey", `pkcs11:token=${process.env.PKCS11_TOKEN_LABEL};type=private;pin-value=${process.env.PKCS11_PIN}`,
        "-outform", "DER",
        "-md", "sha256",
        "-nosmimecap",
        "-out", cmsPath
      ];

      if (chainPath && fs.existsSync(chainPath)) {
        // Correct order: -certfile must come before -out is handled by the array logic
        signArgs.splice(signArgs.indexOf("-out"), 0, "-certfile", chainPath);
      }

      const sign = spawnSync(openssl, signArgs, {
        env: { ...process.env, PKCS11_MODULE_PATH: process.env.PKCS11_MODULE }
      });

      if (sign.status !== 0) {
        throw new Error(`OpenSSL Error: ${sign.stderr.toString()}`);
      }

      // 2️⃣ Generate Timestamp over the Signature (PAdES Requirement)
      console.log("⏳ Requesting RFC3161 timestamp...");
      const cmsBuffer = fs.readFileSync(cmsPath);
      
      // Request timestamp over the CMS file
      const tsQuery = spawnSync(openssl, [
        "ts", "-query", "-data", cmsPath, "-sha256", "-cert"
      ], { encoding: null });

      // 3️⃣ Fetch Timestamp using Fetch (Not cURL)
      const response = await fetch(process.env.TSA_URL, {
        method: "POST",
        headers: { "Content-Type": "application/timestamp-query" },
        body: tsQuery.stdout
      });

      if (!response.ok) throw new Error("TSA Server returned error");
      const tsrBuffer = Buffer.from(await response.arrayBuffer());

      // 4️⃣ Inject Timestamp into the CMS Unsigned Attributes
      const signedDataBuffer = this.injectTimestamp(cmsBuffer, tsrBuffer);
      
      console.log(`✅ Signature Complete: ${signedDataBuffer.length} bytes`);
      return signedDataBuffer;

    } finally {
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

    if (!tsrInfo.timeStampToken) throw new Error("Missing TimeStampToken");

    const signer = signedData.signerInfos[0];
    
    if (!signer.unsignedAttributes) {
      signer.unsignedAttributes = new pkijs.SignedAndUnsignedAttributes({ type: 1, attributes: [] });
    }

    signer.unsignedAttributes.attributes.push(new pkijs.Attribute({
      type: "1.2.840.113549.1.9.16.2.14",
      values: [tsrInfo.timeStampToken.toSchema()]
    }));

    const finalContentInfo = new pkijs.ContentInfo({
      contentType: "1.2.840.113549.1.7.2",
      content: signedData.toSchema()
    });

    return Buffer.from(finalContentInfo.toSchema().toBER(true));
  }
}

export async function signBuffer(pdfBuffer) {
  if (process.env.NODE_ENV === "development") return pdfBuffer;
  
  const pdfWithPlaceholder = plainAddPlaceholder({
    pdfBuffer,
    reason: "TransferGuard Legal Seal",
    signatureLength: SIGNATURE_LENGTH,
  });

  return await new SignPdf().sign(pdfWithPlaceholder, new ExternalSigner());
}