const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");

const app = express();

/* -----------------------------------------------------
   GLOBAL SECURITY HEADERS — FIX ALL ZAP LOW/MEDIUM
------------------------------------------------------ */

app.disable("x-powered-by");

app.use((req, res, next) => {
  // CSP (fix Medium alert)
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

  // FIX: the missing header that caused ZAP Low alert
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");

  // Required for full site isolation
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");

  // Prevent MIME sniffing
  res.setHeader("X-Content-Type-Options", "nosniff");

  // Prevent clickjacking
  res.setHeader("X-Frame-Options", "DENY");

  // Reduce browser permissions
  res.setHeader("Permissions-Policy", "geolocation=()");

  // Disable caching (fix "Non-storable response" warning)
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  next();
});

// -----------------------------------------------------
// CORS + PARSERS
// -----------------------------------------------------
app.use(
  cors({
    origin: ["http://localhost:3001", "http://127.0.0.1:3001"],
    credentials: true,
  })
);

app.use(bodyParser.json());
app.use(cookieParser());

// -----------------------------------------------------
// DB + VULNERABLE LOGIC (unchanged for lab)
// -----------------------------------------------------
const db = new sqlite3.Database(":memory:");

db.serialize(() => {
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT,
      email TEXT
    );
  `);

  db.run(`
    CREATE TABLE transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      amount REAL,
      description TEXT
    );
  `);

  db.run(`
    CREATE TABLE feedback (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user TEXT,
      comment TEXT
    );
  `);

  const passwordHash = crypto.createHash("sha256")
    .update("password123")
    .digest("hex");

  db.run(`INSERT INTO users (username, password_hash, email)
          VALUES ('alice', '${passwordHash}', 'alice@example.com');`);

  db.run(`INSERT INTO transactions (user_id, amount, description)
          VALUES (1, 25.50, 'Coffee shop')`);
  db.run(`INSERT INTO transactions (user_id, amount, description)
          VALUES (1, 100, 'Groceries')`);
});

// -----------------------------------------------------
// SESSION STORE
// -----------------------------------------------------
const sessions = {};

function fastHash(pwd) {
  return crypto.createHash("sha256").update(pwd).digest("hex");
}

function auth(req, res, next) {
  const sid = req.cookies.sid;
  if (!sid || !sessions[sid])
    return res.status(401).json({ error: "Not authenticated" });

  req.user = { id: sessions[sid].userId };
  next();
}

// -----------------------------------------------------
// VULNERABLE LOGIN (unchanged)
// -----------------------------------------------------
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    `SELECT id, username, password_hash FROM users WHERE username = '${username}'`,
    (err, user) => {
      if (!user) return res.status(404).json({ error: "Unknown username" });

      const candidate = fastHash(password);
      if (candidate !== user.password_hash)
        return res.status(401).json({ error: "Wrong password" });

      const sid = `${username}-${Date.now()}`;
      sessions[sid] = { userId: user.id };
      res.cookie("sid", sid, {});

      res.json({ success: true });
    }
  );
});

// -----------------------------------------------------
// OTHER LAB ENDPOINTS (unchanged)
// -----------------------------------------------------
app.get("/me", auth, (req, res) => {
  db.get(
    `SELECT username, email FROM users WHERE id = ${req.user.id}`,
    (err, row) => res.json(row)
  );
});

app.get("/transactions", auth, (req, res) => {
  const q = req.query.q || "";
  db.all(
    `
    SELECT id, amount, description
    FROM transactions
    WHERE user_id = ${req.user.id}
      AND description LIKE '%${q}%'
    ORDER BY id DESC
    `,
    (err, rows) => res.json(rows)
  );
});

app.post("/feedback", auth, (req, res) => {
  const comment = req.body.comment;
  db.get(
    `SELECT username FROM users WHERE id = ${req.user.id}`,
    (err, row) => {
      db.run(
        `INSERT INTO feedback (user, comment) VALUES ('${row.username}', '${comment}')`,
        () => res.json({ success: true })
      );
    }
  );
});

app.get("/feedback", auth, (req, res) => {
  db.all("SELECT user, comment FROM feedback ORDER BY id DESC", (err, rows) =>
    res.json(rows)
  );
});

app.post("/change-email", auth, (req, res) => {
  const newEmail = req.body.email;
  if (!newEmail.includes("@"))
    return res.status(400).json({ error: "Invalid email" });

  db.run(
    `UPDATE users SET email = '${newEmail}' WHERE id = ${req.user.id}`,
    () => res.json({ success: true, email: newEmail })
  );
});

// -----------------------------------------------------
// STATIC ROUTES (headers already applied by middleware)
// -----------------------------------------------------
app.get("/", (req, res) => {
  res.send("FastBank backend running");
});

app.get("/robots.txt", (req, res) => {
  res.type("text/plain").send("User-agent: *\nDisallow:");
});

app.get("/sitemap.xml", (req, res) => {
  res.type("application/xml").send(
    `<?xml version="1.0" encoding="UTF-8"?>
     <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
       <url><loc>http://localhost:3000/</loc></url>
     </urlset>`
  );
});

// -----------------------------------------------------
app.listen(3000, () =>
  console.log("FastBank Version A backend running on http://localhost:3000")
);
