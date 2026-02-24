import { plainAddPlaceholder } from "@signpdf/placeholder-plain";
import { SignPdf } from "@signpdf/signpdf";
import { Signer } from "@signpdf/utils";
import { spawnSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";

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
            const openssl = process.env.OPENSSL_BIN || "/opt/homebrew/opt/openssl@3/bin/openssl";

            // 1️⃣ Generate DETACHED CMS signature
            // We use detached so the PDF doesn't get duplicated inside the signature
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

            if (sign.status !== 0) {
                throw new Error(`OpenSSL Error: ${sign.stderr?.toString()}`);
            }

            // 2️⃣ Generate Timestamp Query
            console.log("⏳ Requesting RFC3161 timestamp...");
            const tsQuery = spawnSync(openssl, [
                "ts", "-query", "-data", cmsPath, "-sha256", "-cert"
            ], { encoding: null });

            if (tsQuery.status !== 0) throw new Error("TS Query failed");

            // 3️⃣ Fetch Timestamp (using fetch for stability)
            const response = await fetch(process.env.TSA_URL || "http://timestamp.sectigo.com", {
                method: "POST",
                headers: { "Content-Type": "application/timestamp-query" },
                body: tsQuery.stdout
            });

            if (!response.ok) throw new Error(`TSA Server returned ${response.status}`);
            const tsrBuffer = Buffer.from(await response.arrayBuffer());

            // 4️⃣ Inject Timestamp Attribute
            const cmsBuffer = fs.readFileSync(cmsPath);
            const signedDataBuffer = this.injectTimestamp(cmsBuffer, tsrBuffer);
            
            console.log(`✅ Signature Complete: ${signedDataBuffer.length} bytes`);
            return signedDataBuffer;

        } finally {
            try {
                fs.rmSync(tmpDir, { recursive: true, force: true });
            } catch (e) { /* ignore cleanup errors */ }
        }
    }

    injectTimestamp(cmsBuffer, tsrBuffer) {
        // Safer conversion of Node Buffer to ArrayBuffer
        const cmsArrayBuffer = new Uint8Array(cmsBuffer).buffer;
        const tsrArrayBuffer = new Uint8Array(tsrBuffer).buffer;

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

        // Add the timestamp token (OID 1.2.840.113549.1.9.16.2.14)
        signer.unsignedAttributes.attributes.push(new pkijs.Attribute({
            type: "1.2.840.113549.1.9.16.2.14",
            values: [tsrInfo.timeStampToken.toSchema()]
        }));

        const finalContentInfo = new pkijs.ContentInfo({
            contentType: "1.2.840.113549.1.7.2",
            content: signedData.toSchema()
        });

        // Use false for Indefinite Length Encoding - often more compatible with PDF injectors
        return Buffer.from(finalContentInfo.toSchema().toBER(false));
    }
}

export async function signBuffer(pdfBuffer) {
    if (process.env.NODE_ENV === "development") return pdfBuffer;
    
    // Reserve space
    const pdfWithPlaceholder = plainAddPlaceholder({
        pdfBuffer,
        reason: "TransferGuard Legal Seal",
        signatureLength: SIGNATURE_LENGTH,
    });

    // Create instances explicitly as in your working 'old' code
    const signPdf = new SignPdf();
    const signerInstance = new ExternalSigner();

    return await signPdf.sign(pdfWithPlaceholder, signerInstance);
}