import express from "express";
import dotenv from "dotenv";
import { connectDB } from "./db/connectDB.js";

import cors from "cors";

import cookieParser from "cookie-parser";

import authRoutes from "./routes/auth.route.js";

import path from "path";

const app = express();
dotenv.config();

const __dirname = path.resolve();

app.use(cors({ origin: "http://localhost:5173", credentials: true }));

app.use(express.json());
app.use(cookieParser());

app.use("/api/auth", authRoutes);

if (process.env.NODE_ENV === "production") {
  app.use(express.static(path.join(__dirname, "/frontend/dist")));
  app.get("*", (req, res) => {
    res.sendFile(path.resolve(__dirname, "frontend", "dist", "index.html"));
  });
}

const port = process.env.PORT || 3000;

app.listen(port, () => {
  connectDB();
  console.log(`Server is listening to the port: ${port}`);
});

//
