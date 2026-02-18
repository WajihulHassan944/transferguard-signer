import { PDFDocument, rgb } from 'pdf-lib';
import crypto from 'crypto';

// pkcs11js is CommonJS → dynamic import
const pkcs11js = (await import('pkcs11js')).default;

export async function signBuffer(pdfBuffer) {
  if (process.env.NODE_ENV === 'development') {
    console.log('⚠️ Dev mode → skipping real signing');
    return pdfBuffer;
  }

  // 1️⃣ Load PDF and add placeholder rectangle
  const pdfDoc = await PDFDocument.load(pdfBuffer);
  const pages = pdfDoc.getPages();
  const firstPage = pages[0];

  // Draw a visible or invisible rectangle for signature (here bottom-right)
  firstPage.drawRectangle({
    x: firstPage.getWidth() - 150,
    y: 50,
    width: 100,
    height: 50,
    color: rgb(1, 1, 1),
    borderColor: rgb(0, 0, 0),
    borderWidth: 1,
  });

  const pdfWithPlaceholder = await pdfDoc.save();

  // 2️⃣ Initialize PKCS11
  const pkcs11 = new pkcs11js.PKCS11();
  pkcs11.load(process.env.PKCS11_LIB);
  pkcs11.C_Initialize();

  let session;

  try {
    const slots = pkcs11.C_GetSlotList(true);
    if (!slots.length) throw new Error('No PKCS11 slots found');

    session = pkcs11.C_OpenSession(
      slots[0],
      pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION
    );

    pkcs11.C_Login(session, pkcs11js.CKU_USER, process.env.TOKEN_PIN);

    const [privateKey] = pkcs11.C_FindObjects(
      session,
      [{ type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY }],
      1
    );

    if (!privateKey) throw new Error('Private key not found');

    // 3️⃣ Sign PDF buffer
    pkcs11.C_SignInit(session, { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS }, privateKey);
    const signature = pkcs11.C_Sign(session, pdfWithPlaceholder);

    // 4️⃣ Append signature to PDF (basic example, you can implement PKCS#7 container)
    const signedPdfBuffer = Buffer.concat([pdfWithPlaceholder, Buffer.from(signature)]);

    pkcs11.C_Logout(session);
    pkcs11.C_CloseSession(session);
    pkcs11.C_Finalize();

    return signedPdfBuffer;

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
