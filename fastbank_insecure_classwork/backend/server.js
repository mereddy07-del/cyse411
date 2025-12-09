const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");

const app = express();

/* ============================================================
   GLOBAL SECURITY HEADERS (Fixes ZAP CSP Medium Warning)
   ============================================================ */
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline'; " +
      "style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data:; " +
      "connect-src 'self'; " +
      "form-action 'self'; " +
      "frame-ancestors 'none';"
  );
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Permissions-Policy", "geolocation=()");
  next();
});

/* ============================================================
   FIX ZAP ALERT — Missing required endpoints
   ZAP scans "/", "/robots.txt", "/sitemap.xml". You MUST define them.
   ============================================================ */
app.get("/", (req, res) => {
  res.type("text/html");
  res.send("<h1>FastBank API Running</h1>");
});

app.get("/robots.txt", (req, res) => {
  res.type("text/plain");
  res.send("User-agent: *\nDisallow:");
});

app.get("/sitemap.xml", (req, res) => {
  res.type("application/xml");
  res.send("<urlset></urlset>");
});

/* ============================================================
   BASIC CORS (Safe)
   ============================================================ */
app.use(
  cors({
    origin: ["http://localhost:3001", "http://127.0.0.1:3001"],
    credentials: true,
  })
);

app.use(bodyParser.json());
app.use(cookieParser());

/* ============================================================
   SQLITE IN-MEMORY DATABASE
   ============================================================ */
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

  const passwordHash = crypto
    .createHash("sha256")
    .update("password123")
    .digest("hex");

  db.run(
    `INSERT INTO users (username, password_hash, email)
     VALUES ('alice', '${passwordHash}', 'alice@example.com');`
  );

  db.run(
    `INSERT INTO transactions (user_id, amount, description)
     VALUES (1, 25.50, 'Coffee shop')`
  );
  db.run(
    `INSERT INTO transactions (user_id, amount, description)
     VALUES (1, 100, 'Groceries')`
  );
});

/* ============================================================
   SIMPLE PREDICTABLE SESSIONS (Assignment requirement)
   ============================================================ */
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

/* ============================================================
   Q4 — LOGIN with vulnerabilities (SQLi + fast hash + predictable session)
   ============================================================ */
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const sql = `
    SELECT id, username, password_hash
    FROM users
    WHERE username = '${username}'
  `; // SQL injection allowed (required for assignment)

  db.get(sql, (err, user) => {
    if (!user) return res.status(404).json({ error: "Unknown username" });

    const candidate = fastHash(password);
    if (candidate !== user.password_hash)
      return res.status(401).json({ error: "Wrong password" });

    const sid = `${username}-${Date.now()}`; // predictable token
    sessions[sid] = { userId: user.id };

    res.cookie("sid", sid, {}); // intentionally insecure
    res.json({ success: true });
  });
});

/* ============================================================
   /me route
   ============================================================ */
app.get("/me", auth, (req, res) => {
  db.get(
    `SELECT username, email FROM users WHERE id = ${req.user.id}`,
    (err, row) => {
      res.json(row);
    }
  );
});

/* ============================================================
   Q1 — SQL Injection in transactions search
   ============================================================ */
app.get("/transactions", auth, (req, res) => {
  const q = req.query.q || "";

  const sql = `
    SELECT id, amount, description
    FROM transactions
    WHERE user_id = ${req.user.id}
      AND description LIKE '%${q}%'
    ORDER BY id DESC
  `; // SQLi allowed for assignment

  db.all(sql, (err, rows) => res.json(rows));
});

/* ============================================================
   Q2 — Stored XSS + SQLi in feedback
   ============================================================ */
app.post("/feedback", auth, (req, res) => {
  const comment = req.body.comment;
  const userId = req.user.id;

  db.get(`SELECT username FROM users WHERE id = ${userId}`, (err, row) => {
    const username = row.username;

    const insert = `
      INSERT INTO feedback (user, comment)
      VALUES ('${username}', '${comment}')
    `; // SQLi stored XSS required

    db.run(insert, () => res.json({ success: true }));
  });
});

app.get("/feedback", auth, (req, res) => {
  db.all(
    "SELECT user, comment FROM feedback ORDER BY id DESC",
    (err, rows) => res.json(rows)
  );
});

/* ============================================================
   Q3 — CSRF + SQLi in change-email
   ============================================================ */
app.post("/change-email", auth, (req, res) => {
  const newEmail = req.body.email;

  if (!newEmail.includes("@"))
    return res.status(400).json({ error: "Invalid email" });

  const sql = `
    UPDATE users SET email = '${newEmail}'
    WHERE id = ${req.user.id}
  `; // SQLi required for assignment

  db.run(sql, () => res.json({ success: true, email: newEmail }));
});

/* ============================================================
   START SERVER
   ============================================================ */
app.listen(3000, () =>
  console.log("FastBank Version A backend running on http://localhost:3000")
);
