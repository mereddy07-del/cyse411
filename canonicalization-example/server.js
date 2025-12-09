// server.js
const express = require("express");
const path = require("path");
const fs = require("fs");
const { body, validationResult } = require("express-validator");

const app = express();

/* ----------------------------------------------------
 * GLOBAL SECURITY HEADERS (first middleware!)
 * --------------------------------------------------*/
app.disable("x-powered-by");

app.use((req, res, next) => {
  // Strong CSP with explicit directives so ZAP
  // does not complain about missing fallbacks.
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self'",
      "connect-src 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "base-uri 'self'"
    ].join("; ")
  );

  // Lock down powerful APIs
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=(), fullscreen=()"
  );

  // Basic hardening
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");

  // Spectre / cross-origin protections
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");

  // Reasonable cache policy (ZAP might call this informational only)
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  next();
});

/* ----------------------------------------------------
 * BODY PARSING + STATIC FILES
 * --------------------------------------------------*/
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

/* ----------------------------------------------------
 * FILE SYSTEM SETUP
 * --------------------------------------------------*/
const BASE_DIR = path.resolve(__dirname, "files");
if (!fs.existsSync(BASE_DIR)) {
  fs.mkdirSync(BASE_DIR, { recursive: true });
}

// Canonicalization helper
function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {
    // ignore bad encoding, treat raw value
  }
  return path.resolve(baseDir, userInput);
}

/* ----------------------------------------------------
 * SECURE /read ROUTE
 * --------------------------------------------------*/
app.post(
  "/read",
  body("filename")
    .exists().withMessage("filename required")
    .bail()
    .isString()
    .trim()
    .notEmpty().withMessage("filename must not be empty")
    .custom((value) => {
      if (value.includes("\0")) throw new Error("null byte not allowed");
      return true;
    }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const filename = req.body.filename;
    const normalized = resolveSafe(BASE_DIR, filename);

    // Prevent breaking out of BASE_DIR
    if (!normalized.startsWith(BASE_DIR + path.sep)) {
      return res.status(403).json({ error: "Path traversal detected" });
    }

    if (!fs.existsSync(normalized)) {
      return res.status(404).json({ error: "File not found" });
    }

    const content = fs.readFileSync(normalized, "utf8");
    res.json({ path: normalized, content });
  }
);

/* ----------------------------------------------------
 * SECURE /read-no-validate ROUTE
 * (kept simple but safe)
 * --------------------------------------------------*/
app.post("/read-no-validate", (req, res) => {
  const filename = req.body.filename || "";

  // Normalize the input
  let safeName = path.normalize(filename);

  // Block ../ and absolute paths
  if (safeName.includes("..") || path.isAbsolute(safeName)) {
    return res.status(400).json({ error: "Invalid filename" });
  }

  const fullPath = resolveSafe(BASE_DIR, safeName);

  // Prevent exiting BASE_DIR
  if (!fullPath.startsWith(BASE_DIR + path.sep)) {
    return res.status(403).json({ error: "Path traversal blocked" });
  }

  if (!fs.existsSync(fullPath)) {
    return res.status(404).json({ error: "File not found", path: fullPath });
  }

  const content = fs.readFileSync(fullPath, "utf8");
  res.json({ path: fullPath, content });
});

/* ----------------------------------------------------
 * SECURE SAMPLE FILE CREATOR
 * --------------------------------------------------*/
app.post("/setup-sample", (req, res) => {
  const samples = {
    "hello.txt": "Hello from safe file!\n",
    "notes/readme.md": "# Readme\nSample readme file"
  };

  for (const key of Object.keys(samples)) {
    // Normalize dictionary keys
    const normalized = path.normalize(key);

    // Block traversal or absolute paths
    if (normalized.includes("..") || path.isAbsolute(normalized)) {
      continue;
    }

    const filePath = resolveSafe(BASE_DIR, normalized);

    // Ensure we stay inside BASE_DIR
    if (!filePath.startsWith(BASE_DIR + path.sep)) {
      continue;
    }

    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(filePath, samples[key], "utf8");
  }

  res.json({ ok: true, base: BASE_DIR });
});

/* ----------------------------------------------------
 * START SERVER
 * --------------------------------------------------*/
if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () =>
    console.log(`Server listening on http://localhost:${port}`)
  );
}

module.exports = app;
