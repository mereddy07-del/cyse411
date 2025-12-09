const express = require("express");
const path = require("path");
const fs = require("fs");
const { body, validationResult } = require("express-validator");

const app = express();

/* ----------------------------------------------------
 * GLOBAL SECURITY HEADERS
 * --------------------------------------------------*/
app.disable("x-powered-by");

app.use((req, res, next) => {
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

  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=(), fullscreen=()"
  );

  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");

  // Spectre protections
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");

  // Universal no-cache
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  next();
});

/* ----------------------------------------------------
 * BODY PARSING
 * --------------------------------------------------*/
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

/* ----------------------------------------------------
 * STATIC FILES (ZAP-FRIENDLY NO-CACHE)
 * --------------------------------------------------*/
app.use(
  express.static(path.join(__dirname, "public"), {
    etag: false,
    lastModified: false,
    maxAge: 0,
    setHeaders: (res) => {
      res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
      res.setHeader("Pragma", "no-cache");
      res.setHeader("Expires", "0");
    }
  })
);

/* ----------------------------------------------------
 * FILE SYSTEM SETUP
 * --------------------------------------------------*/
const BASE_DIR = path.resolve(__dirname, "files");
if (!fs.existsSync(BASE_DIR)) {
  fs.mkdirSync(BASE_DIR, { recursive: true });
}

function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {}
  return path.resolve(baseDir, userInput);
}

/* ----------------------------------------------------
 * SECURE /read ROUTE
 * --------------------------------------------------*/
app.post(
  "/read",
  body("filename")
    .exists()
    .isString()
    .trim()
    .notEmpty()
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
 * --------------------------------------------------*/
app.post("/read-no-validate", (req, res) => {
  const filename = req.body.filename || "";
  let safeName = path.normalize(filename);

  if (safeName.includes("..") || path.isAbsolute(safeName)) {
    return res.status(400).json({ error: "Invalid filename" });
  }

  const fullPath = resolveSafe(BASE_DIR, safeName);

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
    const normalized = path.normalize(key);
    if (normalized.includes("..") || path.isAbsolute(normalized)) continue;

    const filePath = resolveSafe(BASE_DIR, normalized);
    if (!filePath.startsWith(BASE_DIR + path.sep)) continue;

    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

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
