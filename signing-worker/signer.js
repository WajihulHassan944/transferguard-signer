import crypto from "crypto";
import SignPdf from "@signpdf/signpdf";
import plainAddPlaceholder from "@signpdf/placeholder-pdf-lib";

// pkcs11js is CommonJS → dynamic import
const pkcs11js = (await import("pkcs11js")).default;
export async function signBuffer(pdfBuffer) {

  if (process.env.NODE_ENV === "development") {
    console.log("⚠️ Dev mode → skipping real signing");
    return pdfBuffer;
  }

  // 1️⃣ Add signature placeholder
  const pdfWithPlaceholder = plainAddPlaceholder({
    pdfBuffer,
    reason: "TransferGuard Legal Seal",
    signatureLength: 8192, // reserve space
  });

  // 2️⃣ Create PKCS11 instance
  const pkcs11 = new pkcs11js.PKCS11();
  pkcs11.load(process.env.PKCS11_LIB);
  pkcs11.C_Initialize();

  let session;

  try {
    const slots = pkcs11.C_GetSlotList(true);
    if (!slots.length) throw new Error("No PKCS11 slots found");

    session = pkcs11.C_OpenSession(
      slots[0],
      pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION
    );

    pkcs11.C_Login(session, pkcs11js.CKU_USER, process.env.TOKEN_PIN);

    // 🔎 Find first private key on token
    pkcs11.C_FindObjectsInit(session, [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
    ]);

    const [privateKey] = pkcs11.C_FindObjects(session, 1);
    pkcs11.C_FindObjectsFinal(session);

    if (!privateKey) {
      throw new Error("Private key not found on token");
    }

    // 3️⃣ Custom signer for signpdf
    const signer = {
      sign: (data) => {

        pkcs11.C_SignInit(
          session,
          { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS },
          privateKey
        );

        const signature = pkcs11.C_Sign(session, data);

        return Buffer.from(signature);
      },
    };

    const signPdf = new SignPdf();
    const signedPdf = signPdf.sign(pdfWithPlaceholder, signer);

    pkcs11.C_Logout(session);
    pkcs11.C_CloseSession(session);
    pkcs11.C_Finalize();

    return signedPdf;

  } catch (err) {

    try {
      if (session) {
        pkcs11.C_Logout(session);
        pkcs11.C_CloseSession(session);
      }
      pkcs11.C_Finalize();
    } catch (_) {}

    throw err;
  }
}
