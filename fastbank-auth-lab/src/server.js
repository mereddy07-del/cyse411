const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3001;

// ----------------------------------------------------
// Global Security Headers (Fixes ZAP Medium Alerts)
// ----------------------------------------------------
app.disable("x-powered-by");

app.use((req, res, next) => {
  // Strong CSP with no fallback issues
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self'",
      "connect-src 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'"
    ].join("; ")
  );

  // Prevent MIME sniffing
  res.setHeader("X-Content-Type-Options", "nosniff");

  // Clickjacking protection
  res.setHeader("X-Frame-Options", "DENY");

  // Hardening against Spectre (fixes ZAP Low Alert)
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");

  // HSTS (safe for ZAP)
  res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains");

  // Disable caching (stops ZAP "storable content" alerts)
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  next();
});

// ----------------------------------------------------
// App Setup
// ----------------------------------------------------
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static("public"));

// ----------------------------------------------------
// Fake User Database (intentionally weak)
// ----------------------------------------------------
function fastHash(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

const users = [
  {
    id: 1,
    username: "student",
    passwordHash: fastHash("password123")
  }
];

// in-memory session store
const sessions = {}; // token → { userId }

// simple user lookup
function findUser(username) {
  return users.find((u) => u.username === username);
}

// ----------------------------------------------------
// /api/me (existing)
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
// LOGIN (kept intentionally vulnerable; security headers fixed)
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

  // More random session token (still simple, but unpredictable)
  const token = crypto.randomBytes(16).toString("hex");

  sessions[token] = { userId: user.id };

  // FIXED: secure cookie flags (ZAP-approved)
  res.cookie("session", token, {
    httpOnly: true,
    secure: false,     // stays false for localhost so your app does not break
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
// Start server
// ----------------------------------------------------
app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
