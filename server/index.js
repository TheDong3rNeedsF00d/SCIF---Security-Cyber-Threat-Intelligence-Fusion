require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const path = require("path");
const fs = require("fs");

const { initDb } = require("./db/database");
const { auth: authLimiter } = require("./middleware/rateLimit");

const app = express();
const PORT = process.env.PORT || 3001;

const dataDir = path.join(__dirname, "data");
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
    },
  },
}));

app.use(compression());
app.use(express.json());

if (process.env.NODE_ENV !== "production") {
  app.use(cors({ origin: "http://localhost:5173", credentials: true }));
}

const requireAuth = (req, res, next) => {
  const pw = process.env.DASHBOARD_PASSWORD;
  if (!pw) return next();
  if (req.headers["x-scif-token"] !== pw) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
};

app.post("/api/auth", authLimiter, (req, res) => {
  const pw = process.env.DASHBOARD_PASSWORD;
  if (!pw) return res.json({ ok: true });
  if (req.body?.password === pw) return res.json({ ok: true });
  res.status(401).json({ ok: false });
});

app.use("/api/ioc",      requireAuth, require("./routes/ioc"));
app.use("/api/feeds",    requireAuth, require("./routes/feeds"));
app.use("/api/cves",     requireAuth, require("./routes/cves"));
app.use("/api/certs",    requireAuth, require("./routes/certs"));
app.use("/api/exposure", requireAuth, require("./routes/exposure"));
app.use("/api/workbook", requireAuth, require("./routes/workbook"));

const clientBuild = path.join(__dirname, "public");
if (fs.existsSync(clientBuild)) {
  app.use(express.static(clientBuild));
  app.get("*", (_req, res) => res.sendFile(path.join(clientBuild, "index.html")));
}

// sql.js requires async init before server can start
initDb()
  .then(() => {
    app.listen(PORT, () => {
      const configured = ["ABUSEIPDB_KEY", "VIRUSTOTAL_KEY", "THREATFOX_KEY"].filter(k => process.env[k]);
      console.log("[scif] :" + PORT + " | auth=" + !!process.env.DASHBOARD_PASSWORD + " | keys=" + (configured.join(",") || "none"));
      if (!process.env.DASHBOARD_PASSWORD) console.warn("[scif] WARNING: no password set");
    });
  })
  .catch(err => {
    console.error("[scif] failed to initialize database:", err);
    process.exit(1);
  });