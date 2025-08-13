import express from 'express';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import { db } from './db.js';
dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });

function signJWT(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '2h' });
}
function auth(req, res, next) {
  const token = req.cookies?.token;
  if (!token) return res.status(401).json({ error: 'No auth' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}
function requireRole(role) {
  return (req, res, next) => {
    if (req.user?.role !== role) return res.status(403).json({ error: 'Forbidden' });
    next();
  };
}

// ---- AUTH ----
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  const user = await db.get('SELECT * FROM users WHERE email = ? AND is_active = 1', [email]);
  if (!user) return res.status(401).json({ error: 'Credenciales' });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Credenciales' });
  const token = signJWT({ id: user.id, role: user.role, name: user.name, email: user.email });
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax', maxAge: 2 * 60 * 60 * 1000 });
  res.json({ user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

app.post('/api/auth/logout', auth, (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

// ---- USERS (admin) ----
app.get('/api/users', auth, requireRole('admin'), async (req, res) => {
  const rows = await db.all('SELECT id, name, email, role, is_active, created_at FROM users ORDER BY id DESC');
  res.json(rows);
});

app.post('/api/users', auth, requireRole('admin'), async (req, res) => {
  const { name, email, password, role = 'user' } = req.body;
  const hash = await bcrypt.hash(password, 10);
  try {
    const r = await db.run(
      'INSERT INTO users (name, email, password_hash, role) VALUES (?,?,?,?)',
      [name, email, hash, role]
    );
    res.json({ id: r.lastID });
  } catch (e) {
    res.status(400).json({ error: 'Email ya existe' });
  }
});

app.patch('/api/users/:id', auth, requireRole('admin'), async (req, res) => {
  const { role, is_active, name } = req.body;
  const id = req.params.id;
  const user = await db.get('SELECT * FROM users WHERE id = ?', [id]);
  if (!user) return res.status(404).json({ error: 'No existe' });
  await db.run(
    'UPDATE users SET role = COALESCE(?, role), is_active = COALESCE(?, is_active), name = COALESCE(?, name) WHERE id = ?',
    [role, is_active, name, id]
  );
  res.json({ ok: true });
});

app.post('/api/auth/reset-password', auth, requireRole('admin'), async (req, res) => {
  const { userId, newPassword } = req.body;
  const user = await db.get('SELECT * FROM users WHERE id = ?', [userId]);
  if (!user) return res.status(404).json({ error: 'No existe' });
  const hash = await bcrypt.hash(newPassword, 10);
  await db.run('UPDATE users SET password_hash = ? WHERE id = ?', [hash, userId]);
  res.json({ ok: true });
});

// ---- SHIFTS ----
function hoursDiff(a, b) {
  const ms = new Date(b) - new Date(a);
  return Math.max(ms / (1000 * 60 * 60), 0);
}

app.post('/api/shifts/clock-in', auth, async (req, res) => {
  const now = new Date();
  const date = now.toISOString().slice(0,10);
  const open = await db.get('SELECT * FROM shifts WHERE user_id = ? AND date = ? AND clock_out IS NULL', [req.user.id, date]);
  if (open) return res.status(400).json({ error: 'Turno ya abierto' });
  const r = await db.run(
    'INSERT INTO shifts (user_id, date, clock_in) VALUES (?,?,?)',
    [req.user.id, date, now.toISOString()]
  );
  res.json({ id: r.lastID, date, clock_in: now });
});

app.post('/api/shifts/clock-out', auth, async (req, res) => {
  const now = new Date();
  const open = await db.get('SELECT * FROM shifts WHERE user_id = ? AND clock_out IS NULL ORDER BY id DESC LIMIT 1', [req.user.id]);
  if (!open) return res.status(400).json({ error: 'No hay turno abierto' });
  const total = hoursDiff(open.clock_in, now.toISOString());
  const regular = Math.min(total, 8.0);
  const overtime = Math.max(total - 8.0, 0);
  await db.run(
    'UPDATE shifts SET clock_out = ?, regular_hours = ?, overtime_hours = ? WHERE id = ?',
    [now.toISOString(), Number(regular.toFixed(2)), Number(overtime.toFixed(2)), open.id]
  );
  res.json({ id: open.id, total: +total.toFixed(2), regular: +regular.toFixed(2), overtime: +overtime.toFixed(2) });
});

app.get('/api/shifts/my', auth, async (req, res) => {
  const { from, to } = req.query;
  const rows = await db.all(
    `SELECT * FROM shifts WHERE user_id = ? AND date BETWEEN ? AND ? ORDER BY date DESC`,
    [req.user.id, from ?? '0000-01-01', to ?? '9999-12-31']
  );
  res.json(rows);
});

app.get('/api/shifts/user/:id', auth, requireRole('admin'), async (req, res) => {
  const { from, to } = req.query;
  const uid = req.params.id;
  const rows = await db.all(
    `SELECT * FROM shifts WHERE user_id = ? AND date BETWEEN ? AND ? ORDER BY date DESC`,
    [uid, from ?? '0000-01-01', to ?? '9999-12-31']
  );
  res.json(rows);
});

app.patch('/api/shifts/:id', auth, requireRole('admin'), async (req, res) => {
  const { clock_in, clock_out, notes } = req.body;
  const s = await db.get('SELECT * FROM shifts WHERE id = ?', [req.params.id]);
  if (!s) return res.status(404).json({ error: 'No existe' });

  let regular = s.regular_hours, overtime = s.overtime_hours;
  let cin = clock_in ?? s.clock_in;
  let cout = clock_out ?? s.clock_out;
  if (cin && cout) {
    const total = hoursDiff(cin, cout);
    regular = Math.min(total, 8.0);
    overtime = Math.max(total - 8.0, 0);
  }
  await db.run(
    `UPDATE shifts SET clock_in = COALESCE(?, clock_in),
                       clock_out = COALESCE(?, clock_out),
                       regular_hours = ?,
                       overtime_hours = ?,
                       notes = COALESCE(?, notes)
     WHERE id = ?`,
    [clock_in, clock_out, Number(regular.toFixed?.(2) ?? regular), Number(overtime.toFixed?.(2) ?? overtime), notes, req.params.id]
  );
  res.json({ ok: true });
});

app.delete('/api/shifts/:id', auth, requireRole('admin'), async (req, res) => {
  await db.run('DELETE FROM shifts WHERE id = ?', [req.params.id]);
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server on http://localhost:${PORT}`));
