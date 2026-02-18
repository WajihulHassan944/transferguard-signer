import crypto from "crypto";

export async function signBuffer(buffer) {
  // ===== DEV MODE =====
  if (process.env.NODE_ENV === "development") {
    console.log("⚠️ Dev mode → skipping PKCS11 signing");

    const fakeSig = crypto.createHash("sha256").update(buffer).digest();
    return Buffer.concat([buffer, fakeSig]);
  }

  // ===== PRODUCTION MODE (SoftHSM / HSM) =====
  const pkcs11js = (await import("pkcs11js")).default;

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

    // ===== Locate Private Key (ID: 01) =====
    pkcs11.C_FindObjectsInit(session, [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
      { type: pkcs11js.CKA_ID, value: Buffer.from([0x01]) },
    ]);

    const [privateKey] = pkcs11.C_FindObjects(session, 1);
    pkcs11.C_FindObjectsFinal(session);

    if (!privateKey) {
      throw new Error("Private key not found in HSM");
    }

    // ===== Hash PDF =====
    const hash = crypto.createHash("sha256").update(buffer).digest();

    // ===== Initialize Signing =====
    pkcs11.C_SignInit(
      session,
      { mechanism: pkcs11js.CKM_RSA_PKCS },
      privateKey
    );

    // RSA 2048 = 256 bytes
    const signatureBuffer = Buffer.alloc(256);

    const signature = pkcs11.C_Sign(
      session,
      hash,
      signatureBuffer
    );

    pkcs11.C_Logout(session);
    pkcs11.C_CloseSession(session);
    pkcs11.C_Finalize();

    return Buffer.concat([buffer, signature]);

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
