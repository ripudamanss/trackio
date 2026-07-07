const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const crypto = require('node:crypto');
const path = require('path');
const os = require('node:os');

const app = express();
const port = process.env.PORT || 3000;

// Initialize Supabase client
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Simple in-memory session store
const sessions = new Map(); // token -> username
const forgotAttempts = new Map(); // username -> { count: number, lockUntil: number }

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
    if (parts.length >= 2) {
      const name = parts[0].trim();
      let val = parts.slice(1).join('=').trim();
      // Unquote if the value is wrapped in double quotes
      if (val.startsWith('"') && val.endsWith('"')) {
        val = val.slice(1, -1);
      }
      parsed[name] = val;
    }
  });
  req.sessionToken = parsed['tio_session'];
  
  const session = sessions.get(req.sessionToken);
  const SESSION_TIMEOUT = 15 * 60 * 1000; // 15 minutes session timeout
  
  if (session) {
    if (Date.now() - session.lastActive > SESSION_TIMEOUT) {
      sessions.delete(req.sessionToken);
      req.username = null;
    } else {
      session.lastActive = Date.now();
      req.username = session.username;
    }
  } else {
    req.username = null;
  }
  
  next();
});

// Middleware to protect routes
function requireAuth(req, res, next) {
  if (!req.username) {
    return res.status(401).json({ error: 'Unauthorized. Please log in.' });
  }
  next();
}

// Admin Authentication Middleware
function requireAdmin(req, res, next) {
  if (req.username !== 'admin') {
    return res.status(403).json({ error: 'Forbidden. Admin access required.' });
  }
  next();
}

// API Routes

// Signup
app.post('/api/auth/signup', express.json(), async (req, res) => {
  const { username, password, name, securityQuestion, securityAnswer } = req.body;
  if (!username || !password || !name || !securityQuestion || !securityAnswer) {
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
  if (uLower === 'admin') {
    return res.status(400).json({ error: 'Username "admin" is reserved.' });
  }
  
  try {
    const { data: existing, error: existError } = await supabase
      .from('users')
      .select('username')
      .eq('username', uLower);

    if (existError) {
      return res.status(500).json({
        success: false,
        message: existError.message
      });
    }

    if (existing && existing.length > 0) {
      return res.status(400).json({ error: 'Username already taken. Choose another.' });
    }
    
    const hashedPassword = hashPassword(password);
    const hashedAnswer = hashPassword(securityAnswer.trim().toLowerCase());
    
    const { error: insertError } = await supabase
      .from('users')
      .insert({
        username: uLower,
        name: name.trim(),
        password: hashedPassword,
        security_question: securityQuestion,
        security_answer: hashedAnswer,
        force_reset: false
      });

    if (insertError) {
      return res.status(500).json({
        success: false,
        message: insertError.message
      });
    }
    
    // Create session
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { username: uLower, lastActive: Date.now() });
    
    res.setHeader('Set-Cookie', `tio_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000`);
    res.json({ username: uLower, name: name.trim(), forceReset: false });
  } catch (e) {
    console.error('Signup error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

// Login
app.post('/api/auth/login', express.json(), async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Please fill all fields.' });
  }
  const uLower = username.trim().toLowerCase();
  
  try {
    const { data: users, error: loginError } = await supabase
      .from('users')
      .select('*')
      .eq('username', uLower);

    if (loginError) {
      return res.status(500).json({
        success: false,
        message: loginError.message
      });
    }

    const user = users && users[0];
    if (!user) {
      return res.status(400).json({ error: 'Account not found. Please sign up first.' });
    }
    
    if (!verifyPassword(password, user.password)) {
      return res.status(400).json({ error: 'Incorrect password. Try again.' });
    }
    
    // Create session
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { username: uLower, lastActive: Date.now() });
    
    res.setHeader('Set-Cookie', `tio_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000`);
    res.json({ username: uLower, name: user.name, forceReset: !!user.force_reset });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Database error' });
  }
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
app.get('/api/auth/session', async (req, res) => {
  if (!req.username) {
    return res.status(401).json({ error: 'No active session' });
  }
  try {
    // Admin session bypasses users table select
    if (req.username === 'admin') {
      return res.json({ username: 'admin', name: 'Administrator', forceReset: false });
    }

    const { data: users, error: userError } = await supabase
      .from('users')
      .select('name, force_reset')
      .eq('username', req.username);

    if (userError) {
      return res.status(500).json({
        success: false,
        message: userError.message
      });
    }

    const user = users && users[0];
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    res.json({ username: req.username, name: user.name, forceReset: !!user.force_reset });
  } catch (e) {
    console.error('Session check error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

// Change password
app.put('/api/auth/change-password', requireAuth, express.json(), async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword) {
    return res.status(400).json({ error: 'Please fill all fields.' });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters.' });
  }
  
  try {
    const { data: users, error: userError } = await supabase
      .from('users')
      .select('password, force_reset')
      .eq('username', req.username);

    if (userError) {
      return res.status(500).json({
        success: false,
        message: userError.message
      });
    }

    const user = users && users[0];
    if (!user) {
      return res.status(400).json({ error: 'User not found.' });
    }
    
    // Bypass current password check if user is forced to reset
    if (!user.force_reset) {
      if (!currentPassword || !verifyPassword(currentPassword, user.password)) {
        return res.status(400).json({ error: 'Incorrect current password.' });
      }
    }
    
    const hashedNew = hashPassword(newPassword);
    const { error: updateError } = await supabase
      .from('users')
      .update({ password: hashedNew, force_reset: false })
      .eq('username', req.username);

    if (updateError) {
      return res.status(500).json({
        success: false,
        message: updateError.message
      });
    }
    
    res.json({ success: true });
  } catch (e) {
    console.error('Change password error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

// Forgot Password Flow Endpoints

app.post('/api/auth/forgot-question', express.json(), async (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ error: 'Please enter username.' });
  }
  const uLower = username.trim().toLowerCase();
  
  try {
    const { data: users, error } = await supabase
      .from('users')
      .select('security_question')
      .eq('username', uLower);

    if (error) {
      return res.status(500).json({
        success: false,
        message: error.message
      });
    }

    const user = users && users[0];
    if (!user || !user.security_question) {
      return res.status(404).json({ error: 'User or security question not found.' });
    }

    res.json({ question: user.security_question });
  } catch (e) {
    console.error('Forgot question error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/auth/forgot-verify', express.json(), async (req, res) => {
  const { username, answer } = req.body;
  if (!username || !answer) {
    return res.status(400).json({ error: 'Please fill all fields.' });
  }
  const uLower = username.trim().toLowerCase();
  
  const attempts = forgotAttempts.get(uLower) || { count: 0, lockUntil: 0 };
  if (attempts.lockUntil > Date.now()) {
    const minLeft = Math.ceil((attempts.lockUntil - Date.now()) / 60000);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${minLeft} minutes.` });
  }

  try {
    const { data: users, error } = await supabase
      .from('users')
      .select('security_answer')
      .eq('username', uLower);

    if (error) {
      return res.status(500).json({
        success: false,
        message: error.message
      });
    }

    const user = users && users[0];
    if (!user || !user.security_answer) {
      return res.status(404).json({ error: 'Security answer not set for user.' });
    }

    if (!verifyPassword(answer.trim().toLowerCase(), user.security_answer)) {
      attempts.count += 1;
      if (attempts.count >= 5) {
        attempts.lockUntil = Date.now() + 5 * 60 * 1000; // 5 min lock
        attempts.count = 0;
      }
      forgotAttempts.set(uLower, attempts);
      return res.status(400).json({ error: 'Incorrect answer. Try again.' });
    }

    attempts.count = 0;
    forgotAttempts.set(uLower, attempts);
    res.json({ success: true });
  } catch (e) {
    console.error('Forgot verify error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/auth/forgot-reset', express.json(), async (req, res) => {
  const { username, answer, newPassword } = req.body;
  if (!username || !answer || !newPassword) {
    return res.status(400).json({ error: 'Please fill all fields.' });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }
  const uLower = username.trim().toLowerCase();

  try {
    const { data: users, error } = await supabase
      .from('users')
      .select('security_answer')
      .eq('username', uLower);

    if (error) {
      return res.status(500).json({
        success: false,
        message: error.message
      });
    }

    const user = users && users[0];
    if (!user || !user.security_answer) {
      return res.status(404).json({ error: 'User or security answer not found.' });
    }

    if (!verifyPassword(answer.trim().toLowerCase(), user.security_answer)) {
      return res.status(400).json({ error: 'Security answer verification failed.' });
    }

    const hashedNew = hashPassword(newPassword);
    const { error: updateError } = await supabase
      .from('users')
      .update({ password: hashedNew, force_reset: false })
      .eq('username', uLower);

    if (updateError) {
      return res.status(500).json({
        success: false,
        message: updateError.message
      });
    }

    res.json({ success: true });
  } catch (e) {
    console.error('Forgot reset error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

// Admin Panel API Endpoints

app.post('/api/admin/login', express.json(), async (req, res) => {
  const { username, password } = req.body;
  const uLower = (username || '').trim().toLowerCase();
  if (uLower !== 'admin') {
    return res.status(400).json({ error: 'Invalid admin credentials.' });
  }

  try {
    // Check if admin user exists in DB
    const { data: users, error } = await supabase
      .from('users')
      .select('*')
      .eq('username', 'admin');

    if (error) {
      return res.status(500).json({ success: false, message: error.message });
    }

    const adminUser = users && users[0];
    if (adminUser) {
      // Admin exists in DB, verify password
      if (!verifyPassword(password, adminUser.password)) {
        return res.status(400).json({ error: 'Invalid admin credentials.' });
      }
    } else {
      // Admin does not exist in DB yet, verify against env variable or default
      const defaultAdminPass = process.env.ADMIN_PASSWORD || 'admin123';
      if (password !== defaultAdminPass) {
        return res.status(400).json({ error: 'Invalid admin credentials.' });
      }
      
      // Auto-insert admin user into DB so they exist for future logins and password updates
      const hashedPass = hashPassword(password);
      const { error: insertError } = await supabase
        .from('users')
        .insert({
          username: 'admin',
          name: 'Administrator',
          password: hashedPass,
          security_question: 'default',
          security_answer: 'default',
          force_reset: false
        });

      if (insertError) {
        console.warn('Failed to auto-insert admin user:', insertError.message);
      }
    }

    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { username: 'admin', lastActive: Date.now() });
    res.setHeader('Set-Cookie', `tio_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000`);
    res.json({ username: 'admin', name: 'Administrator' });
  } catch (e) {
    console.error('Admin login error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    let query = supabase.from('users').select('username, name, force_reset');
    if (req.query.search) {
      query = query.ilike('username', `%${req.query.search.trim()}%`);
    }
    const { data: users, error } = await query;
    if (error) {
      return res.status(500).json({
        success: false,
        message: error.message
      });
    }
    res.json(users);
  } catch (e) {
    console.error('Admin get users error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/admin/reset-password', requireAdmin, express.json(), async (req, res) => {
  const { username, newPassword, forceReset } = req.body;
  if (!username || !newPassword) {
    return res.status(400).json({ error: 'Please fill all fields.' });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }

  try {
    const hashedPassword = hashPassword(newPassword);
    const { error: updateError } = await supabase
      .from('users')
      .update({
        password: hashedPassword,
        force_reset: !!forceReset
      })
      .eq('username', username);

    if (updateError) {
      return res.status(500).json({
        success: false,
        message: updateError.message
      });
    }

    // Insert into audit logs
    const { error: logError } = await supabase
      .from('audit_logs')
      .insert({
        action: 'password_reset',
        target_user: username,
        performed_by: 'admin'
      });

    if (logError) {
      console.warn('Failed to insert audit log:', logError.message);
    }

    res.json({ success: true });
  } catch (e) {
    console.error('Admin reset password error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/admin/audit-logs', requireAdmin, async (req, res) => {
  try {
    const { data: logs, error } = await supabase
      .from('audit_logs')
      .select('*')
      .order('timestamp', { ascending: false })
      .limit(100);

    if (error) {
      return res.status(500).json({
        success: false,
        message: error.message
      });
    }
    res.json(logs);
  } catch (e) {
    console.error('Admin get audit logs error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

app.put('/api/admin/change-password', requireAdmin, express.json(), async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword) {
    return res.status(400).json({ error: 'Please enter new password.' });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }

  try {
    const hashedNew = hashPassword(newPassword);
    
    // Check if admin row exists, if not insert it, if yes update it
    const { data: users, error: checkError } = await supabase
      .from('users')
      .select('username')
      .eq('username', 'admin');

    if (checkError) {
      return res.status(500).json({ success: false, message: checkError.message });
    }

    let dbError;
    if (users && users.length > 0) {
      const { error } = await supabase
        .from('users')
        .update({ password: hashedNew })
        .eq('username', 'admin');
      dbError = error;
    } else {
      const { error } = await supabase
        .from('users')
        .insert({
          username: 'admin',
          name: 'Administrator',
          password: hashedNew,
          security_question: 'default',
          security_answer: 'default',
          force_reset: false
        });
      dbError = error;
    }

    if (dbError) {
      return res.status(500).json({ success: false, message: dbError.message });
    }

    // Insert into audit logs
    await supabase
      .from('audit_logs')
      .insert({
        action: 'admin_password_change',
        target_user: 'admin',
        performed_by: 'admin'
      });

    res.json({ success: true });
  } catch (e) {
    console.error('Admin change password error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/admin/active-sessions', requireAdmin, async (req, res) => {
  const list = [];
  const now = Date.now();
  const SESSION_TIMEOUT = 15 * 60 * 1000;
  
  for (const [token, sess] of sessions.entries()) {
    if (now - sess.lastActive > SESSION_TIMEOUT) {
      sessions.delete(token);
    } else {
      list.push({
        username: sess.username,
        lastActive: sess.lastActive,
        idleMinutes: Math.round((now - sess.lastActive) / 60000)
      });
    }
  }
  res.json({
    activeCount: list.filter(s => s.username !== 'admin').length,
    sessions: list
  });
});

app.delete('/api/admin/users/:username', requireAdmin, async (req, res) => {
  const username = req.params.username.trim().toLowerCase();
  if (username === 'admin') {
    return res.status(400).json({ error: 'Cannot delete the admin account.' });
  }

  try {
    // Delete transactions first (due to foreign key constraint)
    const { error: txError } = await supabase
      .from('transactions')
      .delete()
      .eq('username', username);

    if (txError) {
      return res.status(500).json({ success: false, message: txError.message });
    }

    // Delete user
    const { error: userError } = await supabase
      .from('users')
      .delete()
      .eq('username', username);

    if (userError) {
      return res.status(500).json({ success: false, message: userError.message });
    }

    // Insert into audit logs
    await supabase
      .from('audit_logs')
      .insert({
        action: 'user_deletion',
        target_user: username,
        performed_by: 'admin'
      });

    res.json({ success: true });
  } catch (e) {
    console.error('Admin delete user error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

// Transactions APIs

// Get transactions
app.get('/api/transactions', requireAuth, async (req, res) => {
  try {
    const { data: transactions, error } = await supabase
      .from('transactions')
      .select('*')
      .eq('username', req.username)
      .order('id', { ascending: false });

    if (error) {
      return res.status(500).json({
        success: false,
        message: error.message
      });
    }

    res.json(transactions);
  } catch (e) {
    console.error('Get transactions error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

// Get single transaction details
app.get('/api/transactions/:id', requireAuth, async (req, res) => {
  try {
    const { data: transactions, error } = await supabase
      .from('transactions')
      .select('*')
      .eq('id', req.params.id)
      .eq('username', req.username);

    if (error) {
      return res.status(500).json({
        success: false,
        message: error.message
      });
    }

    const row = transactions && transactions[0];
    if (!row) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    res.json(row);
  } catch (e) {
    console.error('Get transaction details error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

// Create transaction
app.post('/api/transactions', requireAuth, express.json(), async (req, res) => {
  const { type, amount, desc, date, mode, catId, catEmoji, catLabel, catColor } = req.body;
  if (!type || amount === undefined || amount <= 0 || desc === undefined || !date || !mode || !catId || !catEmoji || !catLabel || !catColor) {
    return res.status(400).json({ error: 'Please enter valid details.' });
  }
  const id = Date.now().toString();
  
  try {
    const { error } = await supabase
      .from('transactions')
      .insert({
        id,
        username: req.username,
        type,
        amount,
        desc,
        date,
        mode,
        catId,
        catEmoji,
        catLabel,
        catColor
      });

    if (error) {
      return res.status(500).json({
        success: false,
        message: error.message
      });
    }

    res.json({ success: true, id });
  } catch (e) {
    console.error('Create transaction error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

// Update transaction
app.put('/api/transactions/:id', requireAuth, express.json(), async (req, res) => {
  const { type, amount, desc, date, mode, catId, catEmoji, catLabel, catColor } = req.body;
  if (!type || amount === undefined || amount <= 0 || desc === undefined || !date || !mode || !catId || !catEmoji || !catLabel || !catColor) {
    return res.status(400).json({ error: 'Please enter valid details.' });
  }
  
  try {
    const { data, error } = await supabase
      .from('transactions')
      .update({
        type,
        amount,
        desc,
        date,
        mode,
        catId,
        catEmoji,
        catLabel,
        catColor
      })
      .eq('id', req.params.id)
      .eq('username', req.username)
      .select();
    
    if (error) {
      return res.status(500).json({
        success: false,
        message: error.message
      });
    }
    
    if (!data || data.length === 0) {
      return res.status(404).json({ error: 'Transaction not found or unauthorized.' });
    }
    res.json({ success: true });
  } catch (e) {
    console.error('Update transaction error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

app.put('/api/transactions/:id/toggle-complete', requireAuth, express.json(), async (req, res) => {
  const { completed } = req.body;
  try {
    const { error } = await supabase
      .from('transactions')
      .update({ completed: !!completed })
      .eq('id', req.params.id)
      .eq('username', req.username);

    if (error) {
      return res.status(500).json({ success: false, message: error.message });
    }
    res.json({ success: true });
  } catch (e) {
    console.error('Toggle complete error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

app.put('/api/transactions/:id/pay-early', requireAuth, async (req, res) => {
  try {
    const d = new Date();
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const date = String(d.getDate()).padStart(2, '0');
    const todayStr = `${year}-${month}-${date}`;

    const { error } = await supabase
      .from('transactions')
      .update({ 
        completed: true,
        date: todayStr
      })
      .eq('id', req.params.id)
      .eq('username', req.username);

    if (error) {
      return res.status(500).json({ success: false, message: error.message });
    }
    res.json({ success: true, date: todayStr });
  } catch (e) {
    console.error('Pay early error:', e);
    res.status(500).json({ error: 'Database error' });
  }
});

// Delete transaction
app.delete('/api/transactions/:id', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('transactions')
      .delete()
      .eq('id', req.params.id)
      .eq('username', req.username)
      .select();

    if (error) {
      return res.status(500).json({
        success: false,
        message: error.message
      });
    }

    if (!data || data.length === 0) {
      return res.status(404).json({ error: 'Transaction not found or unauthorized.' });
    }
    res.json({ success: true });
  } catch (e) {
    console.error('Delete transaction error:', e);
    res.status(500).json({ error: 'Database error' });
  }
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
