import express from "express";
import cors from "cors";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
function makeFriendCode() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "RH-";
  for (let i = 0; i < 6; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

async function genUniqueFriendCode(pool) {
  // try up to 5 random codes; then fall back to a timestamp-based code
  for (let i = 0; i < 5; i++) {
    const code = makeFriendCode();
    const { rows } = await pool.query("select 1 from users where friend_code = $1", [code]);
    if (rows.length === 0) return code;
  }
  return "RH-" + Date.now().toString(36).toUpperCase().slice(-6);
}

const { Pool } = pg;

const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.CORS_ORIGIN, credentials: true }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Neon requires SSL
});

// Health check (easy browser test)
app.get("/api/health", (req, res) => res.json({ ok: true }));

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { email, password, displayName } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "email and password required" });
    }

    const hash = await bcrypt.hash(password, 10);

    // NEW: generate a unique friend code because DB requires it (NOT NULL)
    const friendCode = await genUniqueFriendCode(pool);

    // IMPORTANT: include friend_code in the insert column list
    const q = `
      insert into users (email, password_hash, display_name, friend_code)
      values ($1, $2, $3, $4)
      returning id, email, display_name, friend_code, created_at
    `;
    const { rows } = await pool.query(q, [email, hash, displayName || null, friendCode]);

    res.status(201).json({ user: rows[0] });
  } catch (e) {
    if (String(e.message).includes("unique") && String(e.message).includes("users_email")) {
      return res.status(409).json({ error: "email already exists" });
    }
    console.error(e);
    res.status(500).json({ error: "server error" });
  }
});


// Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "email and password required" });
  const { rows } = await pool.query("select * from users where email=$1", [email]);
  const u = rows[0];
  if (!u) return res.status(401).json({ error: "invalid credentials" });
  const ok = await bcrypt.compare(password, u.password_hash);
  if (!ok) return res.status(401).json({ error: "invalid credentials" });

  const token = jwt.sign({ uid: u.id, email: u.email }, process.env.JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, user: { id: u.id, email: u.email, displayName: u.display_name } });
});

// Messages (public for now; can add JWT later)
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
     values ($1,$2,$3,to_timestamp($4/1000.0),$5) returning id`,
    [uid || null, name || null, text, ts || Date.now(), title || null]
  );
  res.json({ ok: true, id: rows[0].id });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("API listening on", PORT));


