import { plainAddPlaceholder } from "@signpdf/placeholder-plain";
import { SignPdf, Signer } from "@signpdf/signpdf";

const pkcs11js = (await import("pkcs11js")).default;

export async function signBuffer(pdfBuffer) {
  if (process.env.NODE_ENV === "development") {
    console.log("⚠️ Dev mode → skipping signing");
    return pdfBuffer;
  }

  // 1️⃣ Add signature placeholder on original PDF
  const pdfWithPlaceholder = plainAddPlaceholder({
    pdfBuffer,           // untouched PDF
    reason: "TransferGuard Legal Seal",
    signatureLength: 8192, // must match signer buffer
  });

  // 2️⃣ Initialize PKCS#11
  const pkcs11 = new pkcs11js.PKCS11();
  pkcs11.load(process.env.PKCS11_LIB);
  pkcs11.C_Initialize();
  let session;

  try {
    const slots = pkcs11.C_GetSlotList(true);
    if (!slots.length) throw new Error("No PKCS#11 slots found");

    session = pkcs11.C_OpenSession(
      slots[0],
      pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION
    );
    pkcs11.C_Login(session, pkcs11js.CKU_USER, process.env.TOKEN_PIN);

    // 3️⃣ Find first private key
    pkcs11.C_FindObjectsInit(session, [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
    ]);
    const privateKeys = pkcs11.C_FindObjects(session, 1);
    pkcs11.C_FindObjectsFinal(session);

    const privateKey = privateKeys[0];
    if (!privateKey) throw new Error("Private key not found on token");

    // 4️⃣ PKCS#11 signer class
    class PKCS11Signer extends Signer {
      async sign(data) {
        pkcs11.C_SignInit(session, { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS }, privateKey);
        const sigBuffer = Buffer.alloc(8192); // must match placeholder
        const sigLen = pkcs11.C_Sign(data, sigBuffer);
        return sigBuffer.slice(0, sigLen);
      }
    }

    const signerInstance = new PKCS11Signer();

    // 5️⃣ Sign PDF
    const signPdf = new SignPdf();
    const signedPdf = await signPdf.sign(pdfWithPlaceholder, signerInstance);

    // 6️⃣ Cleanup
    pkcs11.C_Logout(session);
    pkcs11.C_CloseSession(session);
    pkcs11.C_Finalize();

    return signedPdf;
  } catch (err) {
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
