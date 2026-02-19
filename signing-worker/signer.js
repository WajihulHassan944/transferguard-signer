import { plainAddPlaceholder } from "@signpdf/placeholder-plain";
import { SignPdf, Signer } from "@signpdf/signpdf";
const pkcs11js = (await import("pkcs11js")).default;
import nodeForge from "node-forge";  // or use pkijs if preferred
import fetch from "node-fetch";  // For fetching timestamp
import crypto from "crypto";

const TSA_URL = "http://timestamp.sectigo.com"; // Sectigo's public timestamp server

// Function to apply TSA (Timestamping)
export async function applyTimestamp(buffer) {
  const hash = crypto.createHash("sha256").update(buffer).digest();

  const res = await fetch(TSA_URL, {
    method: "POST",
    headers: { "Content-Type": "application/timestamp-query" },
    body: hash
  });

  const tsaToken = Buffer.from(await res.arrayBuffer());

  return Buffer.concat([buffer, tsaToken]); // Concatenate the TSA token to the buffer
}

export async function signBuffer(pdfBuffer) {
  if (process.env.NODE_ENV === "development") {
    console.log("⚠️ Dev mode → skipping signing");
    return pdfBuffer;
  }

  console.log("🚀 Starting PDF signing process...");

  // 1️⃣ Add placeholder
  const pdfWithPlaceholder = plainAddPlaceholder({
    pdfBuffer,
    reason: "TransferGuard Legal Seal",
    signatureLength: 12288,  // Increased signatureLength for full certificate chain
  });

  console.log("✅ Placeholder added");

  // 2️⃣ Initialize PKCS#11
  const pkcs11 = new pkcs11js.PKCS11();
  pkcs11.load(process.env.PKCS11_LIB);
  pkcs11.C_Initialize();
  console.log("🔐 PKCS#11 initialized");

  let session;

  try {
    const slots = pkcs11.C_GetSlotList(true);
    console.log("🧩 Available slots:", slots);

    if (!slots.length) throw new Error("No PKCS#11 slots found");

    session = pkcs11.C_OpenSession(
      slots[0],
      pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION
    );

    console.log("🔓 Session opened on slot:", slots[0]);

    pkcs11.C_Login(session, pkcs11js.CKU_USER, process.env.TOKEN_PIN);
    console.log("🔑 Logged into token");

    // 3️⃣ Find private key
    pkcs11.C_FindObjectsInit(session, [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
    ]);

    const privateKeys = pkcs11.C_FindObjects(session, 5);
    pkcs11.C_FindObjectsFinal(session);

    console.log("🔎 Private keys found:", privateKeys.length);

    const privateKey = privateKeys[0];
    if (!privateKey) throw new Error("Private key not found on token");

    console.log("🗝 Using private key handle:", privateKey);

    // 4️⃣ Signer class
    class PKCS11Signer extends Signer {
      async sign(data) {
        console.log("✍️ Signing data...");
        console.log("📦 Data length:", data.length);

        pkcs11.C_SignInit(
          session,
          { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS },
          privateKey
        );

        const sigBuffer = Buffer.alloc(12288);  // Adjusted to 8192 or 12288 for full certificate chain
        const sigLen = pkcs11.C_Sign(session, data, sigBuffer);

        console.log("📏 Signature length:", sigLen, "bytes");

        return sigBuffer.slice(0, sigLen);
      }
    }

    const signerInstance = new PKCS11Signer();

    // 5️⃣ PKCS#7 Wrapper for the raw signature (DER-encoded)
    const createPKCS7Container = (rawSignature, certChain) => {
      const p7 = new nodeForge.pki.createSignedData();
      p7.addCertificate(certChain); // Add all certificates in the chain
      p7.addSigner({
        key: privateKey,
        certificate: certChain[0],  // Use the first certificate as the signer's cert
        digestAlgorithm: nodeForge.pki.oids.sha256,
      });
      p7.sign({ detached: true });
      return p7.toDer();
    };

    const signPdf = new SignPdf();
    const signedPdf = await signPdf.sign(
      pdfWithPlaceholder,
      signerInstance
    );

    // 6️⃣ Apply TSA timestamping to the signed PDF
    const timestampedPdf = await applyTimestamp(signedPdf); // Add TSA

    console.log("🎉 PDF successfully signed and timestamped");

    // 7️⃣ Cleanup
    pkcs11.C_Logout(session);
    pkcs11.C_CloseSession(session);
    pkcs11.C_Finalize();

    console.log("🔚 PKCS#11 session closed");

    return timestampedPdf; // Return the final PDF with timestamp
  } catch (err) {
    console.error("❌ Signing error:", err);

    if (session) {
      try {
        pkcs11.C_Logout(session);
        pkcs11.C_CloseSession(session);
        pkcs11.C_Finalize();
      } catch (_) {}
    }
    throw err;
  }
}
