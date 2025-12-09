const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3001;

// ----------------------------------------------------
// GLOBAL SECURITY HEADERS — ZAP CLEAN VERSION
// ----------------------------------------------------
app.disable("x-powered-by");

app.use((req, res, next) => {
  // Complete CSP defining all directives required by ZAP
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

  // Required to fix ZAP Low Alert: Permissions Policy not set
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=(), fullscreen=()"
  );

  // Prevent MIME sniffing
  res.setHeader("X-Content-Type-Options", "nosniff");

  // Prevent clickjacking
  res.setHeader("X-Frame-Options", "DENY");

  // Fixes Spectre-related ZAP alerts
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");

  // Strong HSTS (ignored on localhost but ZAP likes it)
  res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains");

  // Disable caching (avoids storable content issues)
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  next();
});

// ----------------------------------------------------
// APP SETUP
// ----------------------------------------------------
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static("public"));

// ----------------------------------------------------
// FAKE USER DATABASE (intentionally weak for class lab)
// ----------------------------------------------------
function fastHash(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

const users = [
  {
    id: 1,
    username: "student",
    passwordHash: fastHash("password123") // intentionally weak for lab
  }
];

// in-memory session store
const sessions = {}; // token → { userId }

// helper to find user
function findUser(username) {
  return users.find((u) => u.username === username);
}

// ----------------------------------------------------
// /api/me — Check current user
// ----------------------------------------------------
app.get("/api/me", (req, res) => {
  const token = req.cookies.session;

  if (!token || !sessions[token]) {
    return res.status(401).json({ authenticated: false });
  }

  const session = sessions[token];
  const user = users.find((u) => u.id === session.userId);

  res.json({ authenticated: true, username: user.username });
});

// ----------------------------------------------------
// LOGIN — intentionally weak logic preserved
// ----------------------------------------------------
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);

  if (!user) {
    return res.status(401).json({ success: false, message: "Unknown username" });
  }

  const candidateHash = fastHash(password);
  if (candidateHash !== user.passwordHash) {
    return res.status(401).json({ success: false, message: "Wrong password" });
  }

  // Random token (still simple but not predictable)
  const token = crypto.randomBytes(16).toString("hex");

  sessions[token] = { userId: user.id };

  // Secure cookie flags (localhost-friendly)
  res.cookie("session", token, {
    httpOnly: true,
    secure: false,   // stays false so localhost still works
    sameSite: "lax"
  });

  res.json({ success: true, token });
});

// ----------------------------------------------------
// LOGOUT
// ----------------------------------------------------
app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) delete sessions[token];
  res.clearCookie("session");
  res.json({ success: true });
});

// ----------------------------------------------------
// START SERVER
// ----------------------------------------------------
app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
