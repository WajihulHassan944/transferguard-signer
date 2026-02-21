import { config } from "dotenv";
import express from "express";
import { generatePDF } from "./signing-worker/pdfGenerator.js";
import { signBuffer } from "./signing-worker/signer.js";
import { startAutoSigner } from "./signing-worker/autoSigner.js";

export const app = express();

config({
  path: "./data/config.env",
});


// Using Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.get("/", (req, res) => {
  res.send("Nice working backend by Wajih ul Hassan for signing pdf");
});


app.post("/sign", async (req, res) => {
  try {
    const transferData = req.body;

    // 1️⃣ Generate PDF
    const pdfBuffer = await generatePDF(transferData);

    // 2️⃣ Hardware sign
    const signedBuffer = await signBuffer(pdfBuffer);

 res.setHeader("Content-Type", "application/pdf");
    res.send(signedBuffer);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Signing failed" });
  }
});

startAutoSigner();
