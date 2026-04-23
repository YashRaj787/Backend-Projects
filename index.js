const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

// DB connection
const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "userdb",
  password: "rajput",
  port: 5432,
});

// TEST ROUTE
app.get("/", (req, res) => {
  res.send("Server is running");
});


// ---------- SIGNUP ----------
app.post("/api/signup", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      // 🔥 FIX HERE (no password returned)
      "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email",
      [name, email, hashedPassword]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error");
  }
});


// ---------- LOGIN ----------
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(400).send("User not found");
    }

    const user = result.rows[0];

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).send("Invalid credentials");
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      "secretkey",
      { expiresIn: "1h" }
    );

    res.json({ token });

  } catch (err) {
    console.error(err);
    res.status(500).send("Error");
  }
});


// ---------- AUTH MIDDLEWARE ----------
function authMiddleware(req, res, next) {
  const token = req.headers["authorization"];

  if (!token) return res.status(403).send("Access denied");

  try {
    const verified = jwt.verify(token, "secretkey");
    req.user = verified;
    next();
  } catch {
    res.status(400).send("Invalid token");
  }
}


// ---------- PROTECTED ROUTE ----------
app.get("/api/protected", authMiddleware, (req, res) => {
  res.send("Protected data accessed");
});


// ---------- OPTIONAL ----------
app.post("/api/users", async (req, res) => {
  const { name, email } = req.body;

  try {
    const result = await pool.query(
      "INSERT INTO users (name, email) VALUES ($1, $2) RETURNING *",
      [name, email]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error");
  }
});

app.get("/api/users", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM users");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send("Error");
  }
});


// ---------- START SERVER ----------
app.listen(3000, () => {
  console.log("Server running on port 3000");
});