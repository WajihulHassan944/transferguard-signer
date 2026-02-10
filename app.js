import { config } from "dotenv";
import express from "express";

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

