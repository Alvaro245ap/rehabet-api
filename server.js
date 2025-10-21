import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import pkg from 'pg';
const { Pool } = pkg;

const app = express();

app.use(helmet());
app.use(express.json({ limit: '200kb' }));
app.use(cors({ origin: process.env.CORS_ORIGIN, credentials: true }));

// DB
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Helpers
function signJWT(payload){ return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '12h' }); }
function auth(req,res,next){
  const t=(req.headers.authorization||'').replace(/^Bearer\s+/,'');
  if(!t) return res.status(401).json({error:'Missing token'});
  try{ req.user = jwt.verify(t, process.env.JWT_SECRET); next(); }
  catch{ return res.status(401).json({error:'Invalid token'}); }
}
function randCode(){
  const A='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let s='RH-'; for(let i=0;i<6;i++) s+=A[Math.floor(Math.random()*A.length)];
  return s;
}
async function uniqueFriendCode(client){
  while(true){
    const code = randCode();
    const { rows } = await client.query('SELECT id FROM users WHERE friend_code=$1',[code]);
    if(rows.length===0) return code;
  }
}
import express from "express";
import cors from "cors";

const app = express();

// parse JSON bodies
app.use(express.json());

// CORS (keep your env var CORS_ORIGIN on Render)
app.use(cors({ origin: process.env.CORS_ORIGIN, credentials: true }));

// ✅ Add this simple health route:
app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

// ... your other routes ...
// app.post("/api/register", ...)
// app.post("/api/login", ...)
// app.get("/api/messages", ...)
// app.post("/api/messages", ...)

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("API listening on", PORT));

// Rate limit for auth
const authLimiter = rateLimit({ windowMs: 60_000, max: 20 });
app.use('/api/register', authLimiter);
app.use('/api/login', authLimiter);

// Auth
const registerSchema = z.object({
  email: z.string().email().optional(),
  username: z.string().trim().min(3).max(32).optional(),
  password: z.string().min(8).max(200),
  displayName: z.string().trim().min(1).max(64).optional(),
  lang: z.enum(['en','es']).optional()
});

app.post('/api/register', async (req,res)=>{
  const parse = registerSchema.safeParse(req.body);
  if(!parse.success) return res.status(400).json({error:parse.error.issues});
  const { email, username, password, displayName='Anonymous', lang='en' } = parse.data;

  const client = await pool.connect();
  try{
    await client.query('BEGIN');
    if(email){
      const { rows } = await client.query('SELECT id FROM users WHERE email=$1',[email]);
      if(rows.length) throw new Error('Email in use');
    }
    if(username){
      const { rows } = await client.query('SELECT id FROM users WHERE username=$1',[username]);
      if(rows.length) throw new Error('Username in use');
    }
    const hash = await bcrypt.hash(password, 12);
    const friend_code = await uniqueFriendCode(client);
    const ins = await client.query(
      `INSERT INTO users (email, username, display_name, password_hash, friend_code, lang)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, display_name, friend_code, lang, username, email`,
      [email||null, username||null, displayName, hash, friend_code, lang]
    );
    await client.query('COMMIT');
    const user = ins.rows[0];
    const token = signJWT({ id: user.id, friend_code: user.friend_code });
    res.json({ token, user });
  }catch(e){
    await client.query('ROLLBACK');
    res.status(400).json({ error: e.message || 'Registration failed' });
  }finally{
    client.release();
  }
});

const loginSchema = z.object({
  email: z.string().email().optional(),
  username: z.string().trim().min(3).max(32).optional(),
  password: z.string().min(8).max(200)
});
app.post('/api/login', async (req,res)=>{
  const parse = loginSchema.safeParse(req.body);
  if(!parse.success) return res.status(400).json({error:parse.error.issues});
  const { email, username, password } = parse.data;
  if(!email && !username) return res.status(400).json({error:'Email or username required'});

  const q = email ? 'SELECT * FROM users WHERE email=$1 LIMIT 1'
                  : 'SELECT * FROM users WHERE username=$1 LIMIT 1';
  const { rows } = await pool.query(q, [email || username]);
  const user = rows[0];
  if(!user) return res.status(401).json({error:'Invalid credentials'});

  const ok = await bcrypt.compare(password, user.password_hash);
  if(!ok) return res.status(401).json({error:'Invalid credentials'});

  await pool.query('UPDATE users SET last_login=NOW() WHERE id=$1',[user.id]);

  const token = signJWT({ id:user.id, friend_code:user.friend_code });
  res.json({ token, user: {
    id:user.id, display_name:user.display_name, friend_code:user.friend_code,
    lang:user.lang, username:user.username, email:user.email
  }});
});

app.get('/api/me', auth, async (req,res)=>{
  const { rows } = await pool.query(
    'SELECT id, display_name, friend_code, lang, username, email FROM users WHERE id=$1',
    [req.user.id]
  );
  res.json(rows[0]||null);
});

// Messages
const postMessageSchema = z.object({
  text: z.string().trim().min(1).max(500),
  room: z.string().trim().min(1).max(64).optional().default('global'),
  title: z.string().trim().max(64).optional()
});

app.get('/api/messages', async (req,res)=>{
  const room = String(req.query.room||'global');
  const limit = Math.min(parseInt(req.query.limit||'200',10), 500);
  const { rows } = await pool.query(
    `SELECT m.id, m.text, m.title, m.created_at, m.room,
            u.id as user_id, u.display_name, u.friend_code
     FROM messages m
     JOIN users u ON u.id = m.user_id
     WHERE m.room=$1
     ORDER BY m.created_at ASC
     LIMIT $2`, [room, limit]
  );
  res.json(rows);
});

app.post('/api/messages', auth, async (req,res)=>{
  const parse = postMessageSchema.safeParse(req.body);
  if(!parse.success) return res.status(400).json({error:parse.error.issues});
  const { text, room='global', title=null } = parse.data;
  await pool.query(
    `INSERT INTO messages (user_id, room, text, title) VALUES ($1,$2,$3,$4)`,
    [req.user.id, room, text, title]
  );
  res.json({ ok:true });
});

// Friend requests (optional)
const friendReqSchema = z.object({ toCode: z.string().regex(/^RH-[A-Z0-9]{6}$/) });

app.post('/api/friend-requests', auth, async (req,res)=>{
  const parse = friendReqSchema.safeParse(req.body);
  if(!parse.success) return res.status(400).json({error:parse.error.issues});
  const { toCode } = parse.data;

  const tgt = await pool.query('SELECT id FROM users WHERE friend_code=$1',[toCode]);
  if(!tgt.rows.length) return res.status(404).json({error:'Friend not found'});
  if(tgt.rows[0].id===req.user.id) return res.status(400).json({error:'Cannot friend yourself'});

  try{
    await pool.query(
      `INSERT INTO friend_requests (from_user_id, to_user_id, status)
       VALUES ($1,$2,'pending')`,
      [req.user.id, tgt.rows[0].id]
    );
  }catch(_){} // ignore duplicate pending
  res.json({ ok:true });
});

const port = Number(process.env.PORT||4000);
app.listen(port, ()=>console.log(`API listening on :${port}`));

