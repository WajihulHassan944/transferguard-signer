import { PDFDocument, rgb } from "pdf-lib";
import { plainAddPlaceholder } from "@signpdf/placeholder-plain";
import { SignPdf, Signer } from "@signpdf/signpdf";

const pkcs11js = (await import("pkcs11js")).default;

export async function signBuffer(pdfBuffer) {
  if (process.env.NODE_ENV === "development") {
    console.log("⚠️ Dev mode → skipping real signing");
    return pdfBuffer;
  }

  // 1️⃣ Draw visible rectangle using pdf-lib BEFORE placeholder
  const pdfDoc = await PDFDocument.load(pdfBuffer);
  const firstPage = pdfDoc.getPages()[0];
  firstPage.drawRectangle({
    x: firstPage.getWidth() - 150,
    y: 50,
    width: 120,
    height: 60,
    borderColor: rgb(0, 0, 0),
    borderWidth: 1,
    color: rgb(1, 1, 1),
  });
  const modifiedPdfBuffer = Buffer.from(await pdfDoc.save());

  // 2️⃣ Add signature placeholder AFTER all pdf-lib modifications
  const pdfWithPlaceholder = plainAddPlaceholder({
    pdfBuffer: modifiedPdfBuffer, // pass the modified buffer
    reason: "TransferGuard Legal Seal",
    signatureLength: 8192,
  });

  // 3️⃣ Initialize PKCS#11
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

    // Find first private key
    pkcs11.C_FindObjectsInit(session, [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
    ]);
    const privateKeys = pkcs11.C_FindObjects(session, 1);
    pkcs11.C_FindObjectsFinal(session);

    const privateKey = privateKeys[0];
    if (!privateKey) throw new Error("Private key not found on token");

    // 4️⃣ Custom PKCS#11 signer class
    class PKCS11Signer extends Signer {
      async sign(data) {
        pkcs11.C_SignInit(session, { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS }, privateKey);
        const sigBuffer = Buffer.alloc(8192); // match signatureLength
        const sigLen = pkcs11.C_Sign(data, sigBuffer);
        return sigBuffer.slice(0, sigLen);
      }
    }

    const signerInstance = new PKCS11Signer();

    // 5️⃣ Sign the PDF
    const signPdf = new SignPdf();
    const signedPdf = await signPdf.sign(pdfWithPlaceholder, signerInstance);

    // 6️⃣ Cleanup PKCS#11 session
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
