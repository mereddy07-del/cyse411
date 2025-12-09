const express = require("express");
const app = express();

app.use(express.json());

/* --------------------------------------
   Security Headers (removes ZAP warnings)
--------------------------------------- */

// Disable Express identifying header
app.disable("x-powered-by");

app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", "default-src 'self'");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  next();
});

// Fake "database"
const users = [
  { id: 1, name: "Alice", role: "customer", department: "north" },
  { id: 2, name: "Bob", role: "customer", department: "south" },
  { id: 3, name: "Charlie", role: "support", department: "north" },
];

const orders = [
  { id: 1, userId: 1, item: "Laptop", region: "north", total: 2000 },
  { id: 2, userId: 1, item: "Mouse", region: "north", total: 40 },
  { id: 3, userId: 2, item: "Monitor", region: "south", total: 300 },
  { id: 4, userId: 2, item: "Keyboard", region: "south", total: 60 },
];

// Very simple "authentication" via headers
function fakeAuth(req, res, next) {
  const id = parseInt(req.header("X-User-Id"), 10);

  if (!id) {
    return res.status(401).json({ error: "Unauthenticated: set X-User-Id" });
  }

  const user = users.find((u) => u.id === id);
  if (!user) {
    return res.status(401).json({ error: "Invalid user" });
  }

  req.user = user;
  next();
}

app.use(fakeAuth);

// --------------------------------------
// SECURE ENDPOINT (IDOR FIXED)
// --------------------------------------
app.get("/orders/:id", (req, res) => {
  const orderId = parseInt(req.params.id, 10);
  const order = orders.find((o) => o.id === orderId);

  if (!order) {
    return res.status(404).json({ error: "Order not found" });
  }

  // FIX: Check ownership to prevent IDOR
  if (order.userId !== req.user.id && req.user.role !== "support") {
    return res.status(403).json({ error: "Forbidden: access denied" });
  }

  return res.json(order);
});

// Health check
app.get("/", (req, res) => {
  res.json({
    message: "Access Control Tutorial API",
    currentUser: req.user,
  });
});

// Start server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Secure server running at http://localhost:${PORT}`);
});
