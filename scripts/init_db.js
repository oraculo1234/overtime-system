import { db } from '../db.js';
import bcrypt from 'bcrypt';

await db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS shifts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  date TEXT NOT NULL,
  clock_in TEXT NOT NULL,
  clock_out TEXT,
  regular_hours REAL DEFAULT 0,
  overtime_hours REAL DEFAULT 0,
  notes TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
`);

const adminEmail = 'admin@foragro.local';
const exists = await db.get('SELECT id FROM users WHERE email = ?', [adminEmail]);
if (!exists) {
  const hash = await bcrypt.hash('Admin123*!', 10);
  await db.run(
    'INSERT INTO users (name, email, password_hash, role) VALUES (?,?,?,?)',
    ['Admin', adminEmail, hash, 'admin']
  );
  console.log('Admin creado: admin@foragro.local / Admin123*!');
} else {
  console.log('Admin ya existe');
}
process.exit(0);
