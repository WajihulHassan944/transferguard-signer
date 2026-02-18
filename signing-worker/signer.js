import { plainAddPlaceholder } from "@signpdf/placeholder-plain";
import { SignPdf, Signer } from "@signpdf/signpdf";

const pkcs11js = (await import("pkcs11js")).default;

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
    signatureLength: 8192,
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

    // OPTIONAL: Get key attributes
    const attrs = pkcs11.C_GetAttributeValue(session, privateKey, [
      { type: pkcs11js.CKA_ID },
      { type: pkcs11js.CKA_LABEL },
      { type: pkcs11js.CKA_MODULUS },
    ]);

    console.log("📌 Key ID:", attrs[0]?.value?.toString("hex"));
    console.log("📌 Key Label:", attrs[1]?.value?.toString());
    console.log(
      "📌 Key Size:",
      attrs[2]?.value ? attrs[2].value.length * 8 + " bits" : "unknown"
    );

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

    // DO NOT allocate buffer
    const signature = pkcs11.C_Sign(session, data);

    console.log("📏 Signature length:", signature.length, "bytes");

    return Buffer.from(signature);
  }
}


    const signerInstance = new PKCS11Signer();

    const signPdf = new SignPdf();
    const signedPdf = await signPdf.sign(
      pdfWithPlaceholder,
      signerInstance
    );

    console.log("🎉 PDF successfully signed");

    // 5️⃣ Cleanup
    pkcs11.C_Logout(session);
    pkcs11.C_CloseSession(session);
    pkcs11.C_Finalize();

    console.log("🔚 PKCS#11 session closed");

    return signedPdf;
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
