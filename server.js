const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const MAX_ADVANCE_DAYS = 3;

// ── database ──────────────────────────────────────────────
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

// ── gmail mailer ──────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS
  }
});

// ── middleware ────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  store: new pgSession({ pool, createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'change-me-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, sameSite: 'lax', httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// ── auth middleware ───────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.isAdmin) return res.status(403).json({ error: 'Admin only' });
  next();
}

// ── helpers ───────────────────────────────────────────────
function dateKey(offsetFromToday) {
  const d = new Date();
  d.setHours(0,0,0,0);
  d.setDate(d.getDate() + offsetFromToday);
  return d.toISOString().slice(0,10);
}
function isWithinAdvanceLimit(dateStr) {
  const today = new Date(); today.setHours(0,0,0,0);
  const target = new Date(dateStr);
  const diffDays = Math.round((target - today) / 86400000);
  return diffDays >= 0 && diffDays <= MAX_ADVANCE_DAYS;
}

// ── send email OTP ────────────────────────────────────────
async function sendEmail(to, code) {
  if (!process.env.GMAIL_USER || !process.env.GMAIL_PASS) {
    console.log(`[DEV] Email to ${to}: code is ${code}`);
    return;
  }
  await transporter.sendMail({
    from: `"Court Booking" <${process.env.GMAIL_USER}>`,
    to,
    subject: 'Your court booking verification code',
    html: `
      <div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:24px;">
        <h2 style="margin-bottom:8px;">Court Booking</h2>
        <p style="color:#555;margin-bottom:24px;">Your verification code is:</p>
        <div style="font-size:36px;font-weight:600;letter-spacing:10px;text-align:center;padding:20px;background:#f5f5f3;border-radius:8px;">${code}</div>
        <p style="color:#888;font-size:13px;margin-top:16px;">Valid for 10 minutes. If you didn't request this, ignore this email.</p>
      </div>`
  });
}

// ── OTP code store ────────────────────────────────────────
const otpCodes = new Map(); // email -> { code, expires }

// ── routes: auth ──────────────────────────────────────────

// Check phone exists
app.post('/api/auth/check-phone', async (req, res) => {
  const { phone } = req.body;
  const { rows } = await pool.query('SELECT id, fname, lname FROM users WHERE phone=$1', [phone]);
  if (!rows.length) return res.status(404).json({ error: 'Phone not found' });
  res.json({ fname: rows[0].fname, lname: rows[0].lname });
});

// Login with PIN
app.post('/api/auth/login', async (req, res) => {
  const { phone, pin } = req.body;
  const cleanPin = String(pin).trim();
  console.log('[LOGIN] phone:', phone, 'pin:', JSON.stringify(cleanPin));
  const { rows } = await pool.query('SELECT * FROM users WHERE phone=$1', [phone]);
  if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
  const user = rows[0];
  console.log('[LOGIN] hash:', user.pin_hash);
  // support plain text pins for initial setup (remove after first login)
  let match = false;
  if (user.pin_hash && user.pin_hash.startsWith('$$plain$$')) {
    match = cleanPin === user.pin_hash.replace('$$plain$$', '');
    console.log('[LOGIN] plain match:', match);
    if (match) {
      // upgrade to bcrypt immediately
      const newHash = await bcrypt.hash(cleanPin, 10);
      await pool.query('UPDATE users SET pin_hash=$1 WHERE id=$2', [newHash, user.id]);
      console.log('[LOGIN] upgraded to bcrypt hash');
    }
  } else {
    match = await bcrypt.compare(cleanPin, user.pin_hash);
    console.log('[LOGIN] bcrypt match:', match);
  }
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });
  req.session.userId = user.id;
  req.session.isAdmin = user.is_admin;
  await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));
  res.json({ id: user.id, fname: user.fname, lname: user.lname, apt: user.apt, phone: user.phone, email: user.email, isAdmin: user.is_admin, approved: user.approved });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.post('/api/auth/change-pin', requireAuth, async (req, res) => {
  const { currentPin, newPin } = req.body;
  if (!/^\d{4}$/.test(newPin)) return res.status(400).json({ error: 'PIN must be 4 digits' });
  const { rows } = await pool.query('SELECT pin_hash FROM users WHERE id=$1', [req.session.userId]);
  if (!rows.length) return res.status(404).json({ error: 'User not found' });
  const match = await bcrypt.compare(currentPin, rows[0].pin_hash);
  if (!match) return res.status(401).json({ error: 'Current PIN is incorrect' });
  const newHash = await bcrypt.hash(newPin, 10);
  await pool.query('UPDATE users SET pin_hash=$1 WHERE id=$2', [newHash, req.session.userId]);
  res.json({ ok: true });
});

app.get('/api/auth/me', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  const { rows } = await pool.query('SELECT id,fname,lname,apt,phone,email,is_admin,approved FROM users WHERE id=$1', [req.session.userId]);
  if (!rows.length) return res.status(401).json({ error: 'User not found' });
  const u = rows[0];
  res.json({ id: u.id, fname: u.fname, lname: u.lname, apt: u.apt, phone: u.phone, email: u.email, isAdmin: u.is_admin, approved: u.approved });
});

// ── routes: registration ──────────────────────────────────

// Step 1: Send email OTP
app.post('/api/auth/send-otp', async (req, res) => {
  try {
    const { email, phone } = req.body;
    const existing = await pool.query('SELECT id FROM users WHERE phone=$1', [phone]);
    if (existing.rows.length) return res.status(409).json({ error: 'Phone already registered' });
    const code = Math.floor(1000 + Math.random() * 9000).toString();
    otpCodes.set(email, { code, expires: Date.now() + 10 * 60 * 1000 });
    await sendEmail(email, code);
    res.json({ ok: true });
  } catch(e) {
    console.error('send-otp error:', e.message);
    res.status(500).json({ error: 'Failed to send email: ' + e.message });
  }
});

// Step 2: Verify OTP
app.post('/api/auth/verify-otp', (req, res) => {
  const { email, code } = req.body;
  const entry = otpCodes.get(email);
  if (!entry || entry.code !== code || Date.now() > entry.expires)
    return res.status(400).json({ error: 'Invalid or expired code' });
  res.json({ ok: true });
});

// Step 3: Complete registration
app.post('/api/auth/register', async (req, res) => {
  const { fname, lname, apt, phone, email, pin, code } = req.body;
  const entry = otpCodes.get(email);
  if (!entry || entry.code !== code || Date.now() > entry.expires)
    return res.status(400).json({ error: 'Code expired. Please restart registration.' });
  if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'PIN must be 4 digits' });
  const existing = await pool.query('SELECT id FROM users WHERE phone=$1', [phone]);
  if (existing.rows.length) return res.status(409).json({ error: 'Phone already registered' });
  const pinHash = await bcrypt.hash(pin, 10);
  const { rows } = await pool.query(
    'INSERT INTO users (fname,lname,apt,phone,email,pin_hash,is_admin,approved) VALUES ($1,$2,$3,$4,$5,$6,false,false) RETURNING id,fname,lname,apt,phone,email',
    [fname, lname, apt, phone, email, pinHash]
  );
  otpCodes.delete(email);
  await pool.query(
    'INSERT INTO notifications (type,text,target_user_id) VALUES ($1,$2,$3)',
    ['reg', `${fname} ${lname} (Apt ${apt}) submitted a registration request.`, rows[0].id]
  );
  res.json(rows[0]);
});

// ── routes: bookings ──────────────────────────────────────

app.get('/api/bookings', requireAuth, async (req, res) => {
  const { date } = req.query;
  let query = 'SELECT b.date,b.hour,b.user_id,u.fname,u.lname FROM bookings b JOIN users u ON u.id=b.user_id';
  const params = [];
  if (date) { query += ' WHERE b.date=$1'; params.push(date); }
  query += ' ORDER BY b.date,b.hour';
  const { rows } = await pool.query(query, params);
  res.json(rows);
});

app.post('/api/bookings', requireAuth, async (req, res) => {
  const { date, hour } = req.body;
  if (!isWithinAdvanceLimit(date) && !req.session.isAdmin)
    return res.status(400).json({ error: `Bookings limited to ${MAX_ADVANCE_DAYS} days in advance` });
  // 1 per day check
  const existing = await pool.query(
    'SELECT id FROM bookings WHERE user_id=$1 AND date=$2',
    [req.session.userId, date]
  );
  if (existing.rows.length)
    return res.status(409).json({ error: 'You already have a booking that day' });
  // Slot taken?
  const taken = await pool.query('SELECT id FROM bookings WHERE date=$1 AND hour=$2', [date, hour]);
  if (taken.rows.length) return res.status(409).json({ error: 'Slot already taken' });

  const { rows } = await pool.query(
    'INSERT INTO bookings (user_id,date,hour) VALUES ($1,$2,$3) RETURNING *',
    [req.session.userId, date, hour]
  );
  // Notify admin
  const user = await pool.query('SELECT fname,lname FROM users WHERE id=$1', [req.session.userId]);
  const u = user.rows[0];
  await pool.query(
    'INSERT INTO notifications (type,text,target_date,target_hour) VALUES ($1,$2,$3,$4)',
    ['book', `${u.fname} ${u.lname} booked on ${date} at ${String(hour).padStart(2,'0')}:00.`, date, hour]
  );
  res.json(rows[0]);
});

app.delete('/api/bookings/:date/:hour', requireAuth, async (req, res) => {
  const { date, hour } = req.params;
  const booking = await pool.query('SELECT * FROM bookings WHERE date=$1 AND hour=$2', [date, hour]);
  if (!booking.rows.length) return res.status(404).json({ error: 'Booking not found' });
  if (booking.rows[0].user_id !== req.session.userId && !req.session.isAdmin)
    return res.status(403).json({ error: 'Not your booking' });
  await pool.query('DELETE FROM bookings WHERE date=$1 AND hour=$2', [date, hour]);
  res.json({ ok: true });
});

// ── routes: users (admin) ─────────────────────────────────

app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT id,fname,lname,apt,phone,is_admin,approved,created_at FROM users ORDER BY created_at');
  res.json(rows);
});

app.patch('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { approved } = req.body;
  const { rows } = await pool.query('UPDATE users SET approved=$1 WHERE id=$2 RETURNING *', [approved, req.params.id]);
  res.json(rows[0]);
});

app.post('/api/users/:id/approve', requireAuth, requireAdmin, async (req, res) => {
  const { approved } = req.body;
  const { rows } = await pool.query('UPDATE users SET approved=$1 WHERE id=$2 RETURNING *', [approved, req.params.id]);
  res.json(rows[0]);
});

app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM users WHERE id=$1 AND is_admin=false', [req.params.id]);
  res.json({ ok: true });
});

// ── routes: notifications (admin) ─────────────────────────

app.get('/api/notifications', requireAuth, requireAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM notifications ORDER BY created_at DESC LIMIT 50');
  res.json(rows);
});

app.patch('/api/notifications/read-all', requireAuth, requireAdmin, async (req, res) => {
  await pool.query('UPDATE notifications SET read=true');
  res.json({ ok: true });
});

// ── catch-all: serve frontend ─────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
