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

        const certBuffer = fs.readFileSync(process.env.CERT_FILE);
        const chainBuffer = fs.readFileSync(process.env.INTERMEDIATE_CERT);
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sign-"));
        const dataPath = path.join(tmpDir, "data.bin");
        const sigPath = path.join(tmpDir, "raw.sig");

        fs.writeFileSync(dataPath, bufferToSign);

        try {
            const openssl = process.env.OPENSSL_BIN || "/opt/homebrew/opt/openssl@3/bin/openssl";

            // 1️⃣ Get Raw Signature from Token (pkeyutl is cleaner for raw signing)
            const digest = crypto.createHash("sha256").update(bufferToSign).digest();
            const digestPath = path.join(tmpDir, "digest.bin");
            fs.writeFileSync(digestPath, digest);

            const signArgs = [
                "pkeyutl", "-sign",
                "-engine", "pkcs11",
                "-keyform", "engine",
                "-inkey", `pkcs11:token=${process.env.PKCS11_TOKEN_LABEL};type=private;pin-value=${process.env.PKCS11_PIN}`,
                "-in", digestPath,
                "-out", sigPath,
                "-pkeyopt", "digest:sha256"
            ];

            const sign = spawnSync(openssl, signArgs, {
                env: { ...process.env, PKCS11_MODULE_PATH: process.env.PKCS11_MODULE }
            });

            if (sign.status !== 0) throw new Error(`OpenSSL Sign Failed: ${sign.stderr.toString()}`);
            const rawSignature = fs.readFileSync(sigPath);

            // 2️⃣ Fetch Timestamp
            const tsQuery = spawnSync(openssl, ["ts", "-query", "-digest", digest.toString('hex'), "-sha256", "-cert"], { encoding: null });
            const tsResponse = await fetch(process.env.TSA_URL || "http://timestamp.sectigo.com", {
                method: "POST",
                headers: { "Content-Type": "application/timestamp-query" },
                body: tsQuery.stdout
            });
            const tsrBuffer = Buffer.from(await tsResponse.arrayBuffer());

            // 3️⃣ Build PAdES CMS Container manually
            return this.buildPadesContainer(bufferToSign, certBuffer, chainBuffer, rawSignature, tsrBuffer);

        } finally {
            fs.rmSync(tmpDir, { recursive: true, force: true });
        }
    }

    buildPadesContainer(data, certBuffer, chainBuffer, rawSignature, tsrBuffer) {
        const signedData = new pkijs.SignedData({
            version: 1,
            encapContentInfo: new pkijs.EncapsulatedContentInfo({
                eContentType: "1.2.840.113549.1.7.1" // data
            }),
            signerInfos: [
                new pkijs.SignerInfo({
                    version: 1,
                    sid: new pkijs.IssuerAndSerialNumber({
                        issuer: pkijs.Certificate.fromBER(certBuffer).issuer,
                        serialNumber: pkijs.Certificate.fromBER(certBuffer).serialNumber
                    }),
                    digestAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: "2.16.840.1.101.3.4.2.1" }),
                    signatureAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: "1.2.840.113549.1.1.11" }), // sha256WithRSAEncryption
                    signature: new asn1js.OctetString({ valueHex: rawSignature })
                })
            ],
            certificates: [pkijs.Certificate.fromBER(certBuffer)]
        });

        const signer = signedData.signerInfos[0];

        // Add PAdES Signing Certificate Attribute
        const certHash = crypto.createHash("sha256").update(certBuffer).digest();
        const essSigningCertV2 = new asn1js.Sequence({
            value: [new asn1js.Sequence({
                value: [new asn1js.Sequence({
                    value: [
                        new asn1js.Sequence({ value: [new asn1js.ObjectIdentifier({ value: "2.16.840.1.101.3.4.2.1" })] }),
                        new asn1js.OctetString({ valueHex: certHash })
                    ]
                })]
            })]
        });

        signer.signedAttributes = new pkijs.SignedAndUnsignedAttributes({
            type: 0,
            attributes: [
                new pkijs.Attribute({ type: "1.2.840.113549.1.9.3", values: [new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.7.1" })] }), // contentType
                new pkijs.Attribute({ type: "1.2.840.113549.1.9.5", values: [new asn1js.UTCTime({ valueDate: new Date() })] }), // signingTime
                new pkijs.Attribute({ type: "1.2.840.113549.1.9.4", values: [new asn1js.OctetString({ valueHex: crypto.createHash("sha256").update(data).digest() })] }), // messageDigest
                new pkijs.Attribute({ type: "1.2.840.113549.1.9.16.2.47", values: [essSigningCertV2] }) // signingCertificateV2
            ]
        });

        // Add Timestamp
        const tsrAsn1 = asn1js.fromBER(new Uint8Array(tsrBuffer).buffer);
        const tsrInfo = new pkijs.TimeStampResp({ schema: tsrAsn1.result });
        signer.unsignedAttributes = new pkijs.SignedAndUnsignedAttributes({
            type: 1,
            attributes: [
                new pkijs.Attribute({ type: "1.2.840.113549.1.9.16.2.14", values: [tsrInfo.timeStampToken.toSchema()] })
            ]
        });

        const contentInfo = new pkijs.ContentInfo({
            contentType: "1.2.840.113549.1.7.2",
            content: signedData.toSchema(true)
        });

        return Buffer.from(contentInfo.toSchema().toBER(false));
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