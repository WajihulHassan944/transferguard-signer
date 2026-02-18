"use strict";

import { PDFDocument, rgb } from "pdf-lib";
import { plainAddPlaceholder } from "@signpdf/placeholder-plain";
import { default as SignPdf } from "@signpdf/signpdf"; // only to use instance sign method

// pkcs11js is CommonJS → dynamic import
const pkcs11js = (await import("pkcs11js")).default;

/**
 * Sign a PDF buffer using a PKCS#11 token
 * @param {Buffer} pdfBuffer
 * @returns {Buffer} signed PDF
 */
export async function signBuffer(pdfBuffer) {
  if (process.env.NODE_ENV === "development") {
    console.log("⚠️ Dev mode → skipping real signing");
    return pdfBuffer;
  }

  // 1️⃣ Add placeholder
  const pdfWithPlaceholder = plainAddPlaceholder({
    pdfBuffer,
    reason: "TransferGuard Legal Seal",
    signatureLength: 8192,
  });

  // 2️⃣ Draw visible rectangle on first page
  const pdfDoc = await PDFDocument.load(pdfWithPlaceholder);
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

  const finalPdfBuffer = Buffer.from(await pdfDoc.save());

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
    if (!privateKey) throw new Error("Private key not found");

    // 4️⃣ Custom signer
    const signer = {
      sign: (data) => {
        pkcs11.C_SignInit(session, { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS }, privateKey);
        const sigBuffer = Buffer.alloc(1024);
        const sigLen = pkcs11.C_Sign(data, sigBuffer);
        return sigBuffer.slice(0, sigLen);
      },
    };

    // 5️⃣ Use SignPdf instance properly
    const signPdf = new SignPdf();
    const signedPdf = signPdf.sign(finalPdfBuffer, signer);

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
