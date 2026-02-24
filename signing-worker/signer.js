import { plainAddPlaceholder } from "@signpdf/placeholder-plain";
import { SignPdf } from "@signpdf/signpdf";
import { Signer } from "@signpdf/utils";
import { spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import * as crypto from "crypto";

const SIGNATURE_LENGTH = 35000;

class ExternalSigner extends Signer {
    async sign(bufferToSign) {
        console.log("🚀 Starting PAdES-B-T signing...");

        const certPath = process.env.CERT_FILE;
        const chainPath = process.env.INTERMEDIATE_CERT;

        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sign-"));
        const dataPath = path.join(tmpDir, "data.bin");
        const cmsPath = path.join(tmpDir, "sig.der");

        fs.writeFileSync(dataPath, bufferToSign);

        try {
            const openssl = process.env.OPENSSL_BIN || "/opt/homebrew/opt/openssl@3/bin/openssl";

            // 1️⃣ Generate CMS signature
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
                signArgs.splice(signArgs.indexOf("-out"), 0, "-certfile", chainPath);
            }

            const sign = spawnSync(openssl, signArgs, {
                env: { ...process.env, PKCS11_MODULE_PATH: process.env.PKCS11_MODULE }
            });

            if (sign.status !== 0) throw new Error(sign.stderr?.toString());

            // 2️⃣ Request Timestamp
            const tsQuery = spawnSync(openssl, ["ts", "-query", "-data", cmsPath, "-sha256", "-cert"], { encoding: null });
            const response = await fetch(process.env.TSA_URL || "http://timestamp.sectigo.com", {
                method: "POST",
                headers: { "Content-Type": "application/timestamp-query" },
                body: tsQuery.stdout
            });
            const tsrBuffer = Buffer.from(await response.arrayBuffer());

            // 3️⃣ Inject PAdES Attributes & Timestamp
            const cmsBuffer = fs.readFileSync(cmsPath);
            const signerCertBuffer = fs.readFileSync(certPath);
            const signedDataBuffer = this.injectPadesAttributes(cmsBuffer, tsrBuffer, signerCertBuffer);
            
            return signedDataBuffer;

        } finally {
            fs.rmSync(tmpDir, { recursive: true, force: true });
        }
    }

    injectPadesAttributes(cmsBuffer, tsrBuffer, certBuffer) {
        // Safer conversion of Node Buffer to ArrayBuffer
        const cmsArrayBuffer = cmsBuffer.buffer.slice(cmsBuffer.byteOffset, cmsBuffer.byteOffset + cmsBuffer.byteLength);
        const tsrArrayBuffer = tsrBuffer.buffer.slice(tsrBuffer.byteOffset, tsrBuffer.byteOffset + tsrBuffer.byteLength);
        
        const asn1 = asn1js.fromBER(cmsArrayBuffer);
        const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
        const signedData = new pkijs.SignedData({ schema: contentInfo.content });
        const signer = signedData.signerInfos[0];

        // --- A. ADD ESS-signing-certificate-v2 (PAdES Requirement) ---
        // FIX: Using ESSCertIDv2 (the correct class name for modern pkijs)
        const certHash = crypto.createHash("sha256").update(certBuffer).digest();
        const essSigningCertV2 = new pkijs.ESSSigningCertificateV2({
            certs: [new pkijs.ESSCertIDv2({
                hashAlgorithm: new pkijs.AlgorithmIdentifier({
                    algorithmId: "2.16.840.1.101.3.4.2.1" // OID for SHA-256
                }),
                certHash: new asn1js.OctetString({ valueHex: certHash })
            })]
        });

        // Ensure signedAttributes exists
        if (!signer.signedAttributes) {
            signer.signedAttributes = new pkijs.SignedAndUnsignedAttributes({ type: 0, attributes: [] });
        }

        // Add the signing certificate attribute (OID: 1.2.840.113549.1.9.16.2.47)
        signer.signedAttributes.attributes.push(new pkijs.Attribute({
            type: "1.2.840.113549.1.9.16.2.47", 
            values: [essSigningCertV2.toSchema()]
        }));

        // --- B. ADD Timestamp (T-Level) ---
        const tsrAsn1 = asn1js.fromBER(tsrArrayBuffer);
        const tsrInfo = new pkijs.TimeStampResp({ schema: tsrAsn1.result });
        
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

        return Buffer.from(finalContentInfo.toSchema().toBER(false));
    }
}

export async function signBuffer(pdfBuffer) {
    const pdfWithPlaceholder = plainAddPlaceholder({
        pdfBuffer,
        reason: "TransferGuard Legal Seal",
        signatureLength: SIGNATURE_LENGTH,
    });
    return await new SignPdf().sign(pdfWithPlaceholder, new ExternalSigner());
}