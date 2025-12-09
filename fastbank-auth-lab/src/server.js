const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt"); // kept for lab consistency, even if unused

const app = express();
const PORT = 3001;

// ----------------------------------------------------
// 1. GLOBAL SECURITY HEADERS (MUST BE FIRST)
// ----------------------------------------------------
app.disable("x-powered-by");

app.use((req, res, next) => {
  // Strong, explicit CSP (no fallback issues)
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

  // Permissions Policy (fixes ZAP low alert)
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=(), fullscreen=()"
  );

  // Standard hardening headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");

  // Spectre-related isolation
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");

  // HSTS (has no effect on plain HTTP localhost, but ZAP likes it)
  res.setHeader(
    "Strict-Transport-Security",
    "max-age=63072000; includeSubDomains"
  );

  // No caching (good for auth flows)
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  next();
});

// ----------------------------------------------------
// 2. SIMPLE ROUTES TO ENSURE CSP ON ROOT / ROBOTS / SITEMAP
// ----------------------------------------------------

// Root route – just a simple text response
app.get("/", (req, res) => {
  res.send("FastBank Auth Lab server running");
});

// robots.txt – ZAP scans this, so we define it explicitly
app.get("/robots.txt", (req, res) => {
  res.type("text/plain").send("User-agent: *\nDisallow:");
});

// sitemap.xml – also scanned by ZAP, defined explicitly
app.get("/sitemap.xml", (req, res) => {
  res
    .type("application/xml")
    .send(
      `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://localhost:${PORT}/</loc></url>
</urlset>`
    );
});

// ----------------------------------------------------
// 3. PARSERS + STATIC FILES
// ----------------------------------------------------
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static("public"));

// ----------------------------------------------------
// 4. FAKE USER DATABASE (INTENTIONALLY WEAK FOR LAB)
// ----------------------------------------------------
function fastHash(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

const users = [
  {
    id: 1,
    username: "student",
    passwordHash: fastHash("password123") // intentionally weak for the lab
  }
];

// In-memory session store: token -> { userId }
const sessions = {};

function findUser(username) {
  return users.find((u) => u.username === username);
}

// ----------------------------------------------------
// 5. API: /api/me – WHO AM I?
// ----------------------------------------------------
app.get("/api/me", (req, res) => {
  const token = req.cookies.session;

  if (!token || !sessions[token]) {
    return res.status(401).json({ authenticated: false });
  }

  const session = sessions[token];
  const user = users.find((u) => u.id === session.userId);

  if (!user) {
    return res.status(401).json({ authenticated: false });
  }

  res.json({ authenticated: true, username: user.username });
});

// ----------------------------------------------------
// 6. API: /api/login – INTENTIONALLY SIMPLE AUTH
// ----------------------------------------------------
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);

  if (!user) {
    return res
      .status(401)
      .json({ success: false, message: "Unknown username" });
  }

  // Still using weak hash on purpose for the lab
  const candidateHash = fastHash(password);
  if (candidateHash !== user.passwordHash) {
    return res
      .status(401)
      .json({ success: false, message: "Wrong password" });
  }

  // Random but simple token
  const token = crypto.randomBytes(16).toString("hex");

  sessions[token] = { userId: user.id };

  // Cookie – secure flags but still OK on localhost
  res.cookie("session", token, {
    httpOnly: true,
    secure: false, // keep false so localhost over HTTP keeps working
    sameSite: "lax"
  });

  res.json({ success: true, token });
});

// ----------------------------------------------------
// 7. API: /api/logout
// ----------------------------------------------------
app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) {
    delete sessions[token];
  }
  res.clearCookie("session");
  res.json({ success: true });
});

// ----------------------------------------------------
// 8. START SERVER
// ----------------------------------------------------
app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
