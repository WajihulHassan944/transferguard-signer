import fetch from "node-fetch";
import crypto from "crypto";

const TSA_URL = "http://timestamp.sectigo.com/qualified";

export async function applyTimestamp(buffer) {
  const hash = crypto.createHash("sha256").update(buffer).digest();

  const res = await fetch(TSA_URL, {
    method: "POST",
    headers: { "Content-Type": "application/timestamp-query" },
    body: hash
  });

  const tsaToken = Buffer.from(await res.arrayBuffer());

  return Buffer.concat([buffer, tsaToken]);
}
