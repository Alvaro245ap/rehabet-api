// ----------- TOP: single ESM import block (do not duplicate) -----------
import express from "express";
import cors from "cors";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
// -----------------------------------------------------------------------

const { Pool } = pg;

const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.CORS_ORIGIN, credentials: true }));

// DB pool (Neon)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }  // Neon requires SSL
});

// Health check (for quick browser test)
app.get("/api/health", (req, res) => res.json({ ok: true }));

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { email, password, displayName } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "email and password required" });
    }
    const hash = await bcrypt.hash(password, 10);
    const q = `
      insert into users (email, password_hash, display_name)
      values ($1,$2,$3)
      returning id, email, display_name, created_at
    `;
    const { rows } = await pool.query(q, [email, hash, displayName || null]);
    res.status(201).json({ user: rows[0] });
  } catch (e) {
    if (String(e.message).includes("unique")) {
      return res.status(409).json({ error: "email already exists" });
    }
    console.error(e);
    res.status(500).json({ error: "server error" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "email and password required" });
  }
  const { rows } = await pool.query("select * from users where email=$1", [email]);
  const u = rows[0];
  if (!u) return res.status(401).json({ error: "invalid credentials" });

  const ok = await bcrypt.compare(password, u.password_hash);
  if (!ok) return res.status(401).json({ error: "invalid credentials" });

  const token = jwt.sign(
    { uid: u.id, email: u.email },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
  res.json({
    token,
    user: { id: u.id, email: u.email, displayName: u.display_name }
  });
});

// Messages (public for now; you can secure later with JWT)
app.get("/api/messages", async (_req, res) => {
  const { rows } = await pool.query(
    "select id, uid, name, text, ts, title from messages order by ts asc limit 200"
  );
  res.json(rows);
});

app.post("/api/messages", async (req, res) => {
  const { uid, name, text, ts, title } = req.body || {};
  if (!text) return res.status(400).json({ error: "text required" });

  const { rows } = await pool.query(
    `insert into messages (uid,name,text,ts,title)
     values ($1,$2,$3,to_timestamp($4/1000.0),$5)
     returning id`,
    [uid || null, name || null, text, ts || Date.now(), title || null]
  );
  res.json({ ok: true, id: rows[0].id });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("API listening on", PORT));
