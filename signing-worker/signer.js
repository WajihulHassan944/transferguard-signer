import { plainAddPlaceholder } from "@signpdf/placeholder-plain";
import { SignPdf } from "@signpdf/signpdf";
import { Signer } from "@signpdf/utils";
import { spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

const SIGNATURE_LENGTH = 32768;

import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

class ExternalSigner extends Signer {
  async sign(bufferToSign) {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sign-"));
    const dataPath = path.join(tmpDir, "data.bin");
    const cmsPath = path.join(tmpDir, "sig.der");
    const tsQueryPath = path.join(tmpDir, "tsq.der");
    const tsRespPath = path.join(tmpDir, "tsr.der");

    fs.writeFileSync(dataPath, bufferToSign);

    try {
      // 1️⃣ Create Initial CMS signature
      const sign = spawnSync("openssl", [
        "cms", "-sign", "-binary",
        "-in", dataPath,
        "-signer", process.env.CERT_FILE,
        "-certfile", process.env.INTERMEDIATE_CERT,
        "-engine", "pkcs11", "-keyform", "engine",
        "-inkey", `pkcs11:token=${process.env.PKCS11_TOKEN_LABEL};type=private;pin-value=${process.env.PKCS11_PIN}`,
        "-outform", "DER", "-md", "sha256",
        "-out", cmsPath,
      ]);

      if (sign.status !== 0) throw new Error(sign.stderr?.toString());

      // 2️⃣ Create and Fetch Timestamp (Sectigo)
      spawnSync("openssl", ["ts", "-query", "-data", cmsPath, "-sha256", "-cert", "-out", tsQueryPath]);
      
      spawnSync("curl", ["-s", "-H", "Content-Type: application/timestamp-query", "--data-binary", `@${tsQueryPath}`, "http://timestamp.sectigo.com", "-o", tsRespPath]);

      // 3️⃣ Inject Timestamp Token into CMS using ASN.1
      const cmsBuffer = fs.readFileSync(cmsPath);
      const tsrBuffer = fs.readFileSync(tsRespPath);

      const signedData = this.injectTimestamp(cmsBuffer, tsrBuffer);
      
      console.log(`✅ CMS signature with injected timestamp created (${signedData.length} bytes)`);
      return Buffer.from(signedData);

    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  injectTimestamp(cmsBuffer, tsrBuffer) {
    // Parse the CMS
    const asn1 = asn1js.fromBER(cmsBuffer.buffer.slice(cmsBuffer.byteOffset, cmsBuffer.byteOffset + cmsBuffer.byteLength));
    const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
    const signedData = new pkijs.SignedData({ schema: contentInfo.content });

    // Parse the Timestamp Response (TSR)
    const tsrAsn1 = asn1js.fromBER(tsrBuffer.buffer.slice(tsrBuffer.byteOffset, tsrBuffer.byteOffset + tsrBuffer.byteLength));
    const tsrInfo = new pkijs.TimeStampResp({ schema: tsrAsn1.result });
    
    // We need the 'timeStampToken' part of the response
    const tsToken = tsrInfo.timeStampToken;

    // Add to unsignedAttributes of the first signer
    const signer = signedData.signerInfos[0];
    signer.unsignedAttributes = signer.unsignedAttributes || new pkijs.SignedAndUnsignedAttributes({ type: 1 });
    
    signer.unsignedAttributes.attributes.push(new pkijs.Attribute({
      type: "1.2.840.113549.1.9.16.2.14", // id-aa-timeStampToken
      values: [tsToken.toSchema()]
    }));

    return signedData.toContentInfo().toBER(false);
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