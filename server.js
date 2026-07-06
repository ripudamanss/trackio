const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const path = require('path');
const os = require('node:os');

const app = express();
const port = process.env.PORT || 3000;

// Initialize SQLite database (use /tmp on Vercel as filesystem is read-only)
const dbPath = process.env.VERCEL
  ? path.join('/tmp', 'database.db')
  : path.join(__dirname, 'database.db');
const db = new DatabaseSync(dbPath);

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    password TEXT NOT NULL
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    type TEXT NOT NULL,
    amount REAL NOT NULL,
    desc TEXT NOT NULL,
    date TEXT NOT NULL,
    mode TEXT NOT NULL,
    catId TEXT NOT NULL,
    catEmoji TEXT NOT NULL,
    catLabel TEXT NOT NULL,
    catColor TEXT NOT NULL,
    FOREIGN KEY(username) REFERENCES users(username)
  )
`);

// Simple in-memory session store
const sessions = new Map(); // token -> username

// Helper functions for password hashing
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedValue) {
  const parts = storedValue.split(':');
  if (parts.length !== 2) return false;
  const [salt, originalHash] = parts;
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return hash === originalHash;
}

// Session Parsing Middleware
app.use((req, res, next) => {
  const cookies = req.headers.cookie || '';
  const parsed = {};
  cookies.split(';').forEach(c => {
    const parts = c.split('=');
    if (parts.length === 2) {
      parsed[parts[0].trim()] = parts[1].trim();
    }
  });
  req.sessionToken = parsed['tio_session'];
  req.username = sessions.get(req.sessionToken);
  next();
});

// Middleware to protect routes
function requireAuth(req, res, next) {
  if (!req.username) {
    return res.status(401).json({ error: 'Unauthorized. Please log in.' });
  }
  next();
}

// API Routes

// Signup
app.post('/api/auth/signup', express.json(), (req, res) => {
  const { username, password, name } = req.body;
  if (!username || !password || !name) {
    return res.status(400).json({ error: 'Please fill all fields.' });
  }
  const uLower = username.trim().toLowerCase();
  
  if (uLower.length < 3) {
    return res.status(400).json({ error: 'Username must be at least 3 characters.' });
  }
  if (!/^[a-z0-9_]+$/.test(uLower)) {
    return res.status(400).json({ error: 'Username can only contain lowercase letters, numbers, underscores.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }
  
  const checkUser = db.prepare('SELECT username FROM users WHERE username = ?');
  const existing = checkUser.get(uLower);
  if (existing) {
    return res.status(400).json({ error: 'Username already taken. Choose another.' });
  }
  
  const hashedPassword = hashPassword(password);
  
  const insertUser = db.prepare('INSERT INTO users (username, name, password) VALUES (?, ?, ?)');
  insertUser.run(uLower, name.trim(), hashedPassword);
  
  // Create session
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, uLower);
  
  res.setHeader('Set-Cookie', `tio_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000`);
  res.json({ username: uLower, name: name.trim() });
});

// Login
app.post('/api/auth/login', express.json(), (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Please fill all fields.' });
  }
  const uLower = username.trim().toLowerCase();
  
  const getUser = db.prepare('SELECT * FROM users WHERE username = ?');
  const user = getUser.get(uLower);
  if (!user) {
    return res.status(400).json({ error: 'Account not found. Please sign up first.' });
  }
  
  if (!verifyPassword(password, user.password)) {
    return res.status(400).json({ error: 'Incorrect password. Try again.' });
  }
  
  // Create session
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, uLower);
  
  res.setHeader('Set-Cookie', `tio_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000`);
  res.json({ username: uLower, name: user.name });
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  if (req.sessionToken) {
    sessions.delete(req.sessionToken);
  }
  res.setHeader('Set-Cookie', 'tio_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');
  res.json({ success: true });
});

// Session check
app.get('/api/auth/session', (req, res) => {
  if (!req.username) {
    return res.status(401).json({ error: 'No active session' });
  }
  const getUser = db.prepare('SELECT name FROM users WHERE username = ?');
  const user = getUser.get(req.username);
  if (!user) {
    return res.status(401).json({ error: 'User not found' });
  }
  res.json({ username: req.username, name: user.name });
});

// Change password
app.put('/api/auth/change-password', requireAuth, express.json(), (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Please fill all fields.' });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters.' });
  }
  
  const getUser = db.prepare('SELECT password FROM users WHERE username = ?');
  const user = getUser.get(req.username);
  if (!user) {
    return res.status(400).json({ error: 'User not found.' });
  }
  
  if (!verifyPassword(currentPassword, user.password)) {
    return res.status(400).json({ error: 'Incorrect current password.' });
  }
  
  const hashedNew = hashPassword(newPassword);
  const updatePass = db.prepare('UPDATE users SET password = ? WHERE username = ?');
  updatePass.run(hashedNew, req.username);
  
  res.json({ success: true });
});

// Get transactions
app.get('/api/transactions', requireAuth, (req, res) => {
  const getTx = db.prepare('SELECT * FROM transactions WHERE username = ? ORDER BY id DESC');
  const rows = getTx.all(req.username);
  res.json(rows);
});

// Get single transaction details
app.get('/api/transactions/:id', requireAuth, (req, res) => {
  const getTx = db.prepare('SELECT * FROM transactions WHERE id = ? AND username = ?');
  const row = getTx.get(req.params.id, req.username);
  if (!row) {
    return res.status(404).json({ error: 'Transaction not found' });
  }
  res.json(row);
});

// Create transaction
app.post('/api/transactions', requireAuth, express.json(), (req, res) => {
  const { type, amount, desc, date, mode, catId, catEmoji, catLabel, catColor } = req.body;
  if (!type || amount === undefined || amount <= 0 || !desc || !date || !mode || !catId || !catEmoji || !catLabel || !catColor) {
    return res.status(400).json({ error: 'Please enter valid details.' });
  }
  const id = Date.now().toString();
  
  const insertTx = db.prepare(`
    INSERT INTO transactions (id, username, type, amount, desc, date, mode, catId, catEmoji, catLabel, catColor)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  insertTx.run(id, req.username, type, amount, desc, date, mode, catId, catEmoji, catLabel, catColor);
  
  res.json({ success: true, id });
});

// Update transaction
app.put('/api/transactions/:id', requireAuth, express.json(), (req, res) => {
  const { type, amount, desc, date, mode, catId, catEmoji, catLabel, catColor } = req.body;
  if (!type || amount === undefined || amount <= 0 || !desc || !date || !mode || !catId || !catEmoji || !catLabel || !catColor) {
    return res.status(400).json({ error: 'Please enter valid details.' });
  }
  
  const updateTx = db.prepare(`
    UPDATE transactions
    SET type = ?, amount = ?, desc = ?, date = ?, mode = ?, catId = ?, catEmoji = ?, catLabel = ?, catColor = ?
    WHERE id = ? AND username = ?
  `);
  const info = updateTx.run(type, amount, desc, date, mode, catId, catEmoji, catLabel, catColor, req.params.id, req.username);
  
  if (info.changes === 0) {
    return res.status(404).json({ error: 'Transaction not found or unauthorized.' });
  }
  res.json({ success: true });
});

// Delete transaction
app.delete('/api/transactions/:id', requireAuth, (req, res) => {
  const deleteTx = db.prepare('DELETE FROM transactions WHERE id = ? AND username = ?');
  const info = deleteTx.run(req.params.id, req.username);
  if (info.changes === 0) {
    return res.status(404).json({ error: 'Transaction not found or unauthorized.' });
  }
  res.json({ success: true });
});

// Serve frontend files
app.use(express.static(path.join(__dirname)));

// Fallback to index.html for UI SPA routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

function getLocalIpAddresses() {
  const ips = [];
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        ips.push(iface.address);
      }
    }
  }
  return ips;
}

if (require.main === module) {
  app.listen(port, '0.0.0.0', () => {
    console.log(`Server running locally at http://localhost:${port}`);
    const localIps = getLocalIpAddresses();
    if (localIps.length > 0) {
      console.log('Or access it over WiFi / local network:');
      localIps.forEach(ip => {
        console.log(`  http://${ip}:${port}`);
      });
    }
  });
}

module.exports = app;
