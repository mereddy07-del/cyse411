// server.js
const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();

const app = express();

/* -------------------------------------------------------
   GLOBAL SECURITY HEADERS — FIXES ALL ZAP COMPLAINTS
------------------------------------------------------- */
app.disable("x-powered-by");

app.use((req, res, next) => {
  // Full CSP with required fallback directives
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

  // REQUIRED to fix “Insufficient Site Isolation Against Spectre”
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");

  // Additional resource protections
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");

  // Basic hardening
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");

  // Disable powerful APIs
  res.setHeader("Permissions-Policy", "geolocation=()");

  // Static files may be cached PRIVATELY (ZAP does NOT flag this)
  res.setHeader("Cache-Control", "private, max-age=3600");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");

  next();
});

/* -------------------------------------------------------
   APP MIDDLEWARE
------------------------------------------------------- */
app.use(
  cors({
    origin: ["http://localhost:3001", "http://127.0.0.1:3001"],
    credentials: true,
  })
);

app.use(bodyParser.json());
app.use(cookieParser());

/* -------------------------------------------------------
   DATABASE INIT
------------------------------------------------------- */
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

  const passwordHash = crypto.createHash("sha256").update("password123").digest("hex");

  db.run(`INSERT INTO users (username, password_hash, email)
          VALUES ('alice', '${passwordHash}', 'alice@example.com');`);

  db.run(`INSERT INTO transactions (user_id, amount, description) VALUES (1, 25.50, 'Coffee shop')`);
  db.run(`INSERT INTO transactions (user_id, amount, description) VALUES (1, 100, 'Groceries')`);
});

/* -------------------------------------------------------
   SESSION MANAGEMENT
------------------------------------------------------- */
const sessions = {};

function fastHash(pwd) {
  return crypto.createHash("sha256").update(pwd).digest("hex");
}

function auth(req, res, next) {
  const sid = req.cookies.sid;
  if (!sid || !sessions[sid]) return res.status(401).json({ error: "Not authenticated" });
  req.user = { id: sessions[sid].userId };
  next();
}

/* -------------------------------------------------------
   AUTH ENDPOINTS (intentionally weak)
------------------------------------------------------- */
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // Vulnerable SQL — left unchanged for assignment purposes
  const sql = `SELECT id, username, password_hash FROM users WHERE username = '${username}'`;

  db.get(sql, (err, user) => {
    if (!user) return res.status(404).json({ error: "Unknown username" });

    const candidate = fastHash(password);
    if (candidate !== user.password_hash) {
      return res.status(401).json({ error: "Wrong password" });
    }

    const sid = crypto.randomBytes(16).toString("hex");
    sessions[sid] = { userId: user.id };

    res.cookie("sid", sid, {
      httpOnly: true,
      sameSite: "lax",
      secure: false, // localhost-friendly
    });

    res.json({ success: true });
  });
});

app.get("/me", auth, (req, res) => {
  db.get(`SELECT username, email FROM users WHERE id = ${req.user.id}`, (err, row) => {
    res.json(row);
  });
});

/* -------------------------------------------------------
   TRANSACTIONS (SQLi intentional for class)
------------------------------------------------------- */
app.get("/transactions", auth, (req, res) => {
  const q = req.query.q || "";
  const sql = `
    SELECT id, amount, description
    FROM transactions
    WHERE user_id = ${req.user.id}
      AND description LIKE '%${q}%'
    ORDER BY id DESC
  `;
  db.all(sql, (err, rows) => res.json(rows));
});

/* -------------------------------------------------------
   FEEDBACK (stored XSS + SQLi kept for lab)
------------------------------------------------------- */
app.post("/feedback", auth, (req, res) => {
  const comment = req.body.comment;

  db.get(`SELECT username FROM users WHERE id = ${req.user.id}`, (err, row) => {
    const username = row.username;
    const insert = `
      INSERT INTO feedback (user, comment)
      VALUES ('${username}', '${comment}')
    `;
    db.run(insert, () => {
      res.json({ success: true });
    });
  });
});

app.get("/feedback", auth, (req, res) => {
  db.all("SELECT user, comment FROM feedback ORDER BY id DESC", (err, rows) => {
    res.json(rows);
  });
});

/* -------------------------------------------------------
   CHANGE EMAIL (CSRF + SQLi left intentionally)
------------------------------------------------------- */
app.post("/change-email", auth, (req, res) => {
  const newEmail = req.body.email;

  if (!newEmail.includes("@")) return res.status(400).json({ error: "Invalid email" });

  const sql = `
    UPDATE users SET email = '${newEmail}' WHERE id = ${req.user.id}
  `;
  db.run(sql, () => {
    res.json({ success: true, email: newEmail });
  });
});

/* -------------------------------------------------------
   STATIC PATHS (required for ZAP checks)
------------------------------------------------------- */
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

/* -------------------------------------------------------
   START SERVER
------------------------------------------------------- */
app.listen(3000, () => console.log("FastBank backend running at http://localhost:3000"));
