// server.js - HostNet API (Ultra-Secure Production Version)
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs').promises;
const path = require('path');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
const { body, validationResult, param, query } = require('express-validator');

// === Initialize App ===
const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || 'https://hostnetapi.onrender.com';

// === Validate Environment ===
if (!process.env.JWT_SECRET) {
  console.error("❌ FATAL: JWT_SECRET is not set. Use a strong 32+ char secret.");
  process.exit(1);
}
if (!process.env.MONGO_URI) {
  console.error("❌ FATAL: MONGO_URI is not set.");
  process.exit(1);
}

// === Security Middleware ===
app.use(helmet({
  contentSecurityPolicy: false,
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  frameguard: { action: 'deny' },
  referrerPolicy: { policy: 'no-referrer' },
  hidePoweredBy: true
}));

app.use(cors({
  origin: ['https://hostnet.wiki', 'https://www.hostnet.wiki'],
  credentials: true
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// === Rate Limiting ===
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => req.body.email || req.ip,
  message: { error: 'Too many login attempts. Try again later.' }
});

const emailLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  keyGenerator: (req) => req.body.email || req.ip,
  message: { error: 'Too many emails sent. Try again later.' }
});

// === Database Connection ===
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => {
    console.error('❌ MongoDB connection failed:', err.message);
    process.exit(1);
  });

// === Email Transporter ===
let transporter = null;
if (process.env.APP_E && process.env.APP_P) {
  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.APP_E,
      pass: process.env.APP_P
    },
    tls: { rejectUnauthorized: false }
  });

  transporter.verify()
    .then(() => console.log('📧 Email server ready'))
    .catch(err => console.warn('⚠️ Email not configured:', err.message));
}

// === Schemas (Secure & Indexed) ===
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^[a-zA-Z0-9_]+$/, 'Invalid characters in username']
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password_hash: { type: String, required: true },
  verified: { type: Boolean, default: false },
  verificationToken: { type: String },
  verificationExpiry: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

const profileSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, index: true },
  name: { type: String, default: '', maxlength: 50 },
  avatar: { type: String, default: '', match: [/^https?:\/\//i, 'Must be valid HTTPS URL'] },
  banner: { type: String, default: '', match: [/^https?:\/\//i, 'Must be valid HTTPS URL'] },
  bio: { type: String, default: '', maxlength: 500 },
  links: [{ url: String, title: String }],
  theme: { type: String, default: 'light', enum: ['light', 'dark'] },
  videoUrl: { type: String, default: '', match: [/^https?:\/\//i, 'Must be valid HTTPS URL'] },
  videoPosition: {
    top: { type: Number, min: 0, max: 100, default: 50 },
    left: { type: Number, min: 0, max: 100, default: 50 }
  }
});

const clickSchema = new mongoose.Schema({
  username: { type: String, required: true, index: true },
  url: { type: String, required: true },
  count: { type: Number, default: 0, min: 0 }
});

// ✅ Secure View Schema: IP hashed for GDPR compliance
const viewSchema = new mongoose.Schema({
  username: { type: String, required: true, index: true },
  total: { type: Number, default: 0 },
  daily: { type: Map, of: Number, default: {} },
  ipHashes: { type: Map, of: Date, default: {} } // Store hash → date
});

// === Models ===
const User = mongoose.model('User', userSchema);
const Profile = mongoose.model('Profile', profileSchema);
const Click = mongoose.model('Click', clickSchema);
const View = mongoose.model('View', viewSchema);

// === Helper Functions ===

// Generate secure JWT
function generateJWT(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m' });
}

// Verify JWT
function verifyJWT(token) {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return null;
  }
}

// Hash IP for privacy (prevents GDPR violations)
function hashIP(ip, salt = 'hostnet-view-2024') {
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(ip + salt).digest('hex');
}

// Validate inputs
function validateUsername(username) {
  if (!username || username.length < 3 || username.length > 20) return 'Username must be 3–20 chars.';
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return 'Only letters, numbers, underscore.';
  return null;
}

function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email) ? null : 'Invalid email.';
}

function validatePassword(password) {
  return password && password.length >= 8 ? null : 'Password must be at least 8 chars.';
}

// Load email template
async function getEmailTemplate(type) {
  const replacements = {
    verification: {
      TITLE: 'Verify Your HostNet Account',
      SUBJECT: 'Verify Your Email',
      MESSAGE: 'Click the button below to verify your email address.',
      BUTTON: 'Verify Email',
      EXPIRY: '24 hours'
    },
    warning: {
      TITLE: 'Account Deletion Warning',
      SUBJECT: 'Verify Now or Account Will Be Deleted',
      MESSAGE: 'Your unverified account will be deleted in 24 hours.',
      BUTTON: 'Verify Now',
      EXPIRY: '24 hours'
    },
    deleted: {
      TITLE: 'Account Deleted',
      SUBJECT: 'Your Account Was Deleted',
      MESSAGE: 'Your account was deleted due to unverified email.',
      BUTTON: 'Sign Up Again',
      EXPIRY: 'n/a'
    }
  };

  const tmpl = await fs.readFile(path.join(__dirname, 'email.html'), 'utf8').catch(() => `
    <p>Hello,</p>
    <p>${replacements[type]?.MESSAGE}</p>
    <a href="[VERIFICATION_LINK]">[BUTTON]</a>
    <p>Link expires in [EXPIRY].</p>
  `);

  const r = replacements[type] || {};
  return tmpl
    .replace(/\[TITLE\]/g, escapeHtml(r.TITLE))
    .replace(/\[SUBJECT\]/g, escapeHtml(r.SUBJECT))
    .replace(/\[MESSAGE\]/g, escapeHtml(r.MESSAGE))
    .replace(/\[BUTTON\]/g, escapeHtml(r.BUTTON))
    .replace(/\[EXPIRY\]/g, escapeHtml(r.EXPIRY));
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// === Routes ===

// POST /api/register
app.post('/api/register',
  body('username').trim().escape(),
  body('email').normalizeEmail(),
  body('password').isLength({ min: 8 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });

    const { username, email, password } = req.body;

    if (validateUsername(username)) return res.status(400).json({ error: 'Invalid username' });
    if (validateEmail(email)) return res.status(400).json({ error: 'Invalid email' });
    if (validatePassword(password)) return res.status(400).json({ error: 'Weak password' });

    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      const exists = await User.findOne({ $or: [{ email }, { username }] }).session(session);
      if (exists) {
        await new Promise(r => setTimeout(r, 800)); // Prevent enumeration
        await session.abortTransaction();
        session.endSession();
        return res.status(400).json({ error: 'Invalid or already registered.' });
      }

      const hashed = await bcrypt.hash(password, 12);
      const token = uuidv4();
      const expiry = new Date(Date.now() + 24 * 3600000);

      const user = new User({
        username, email, password_hash: hashed,
        verificationToken: token,
        verificationExpiry: expiry
      });
      await user.save({ session });

      await new Profile({ username, name: username }).save({ session });

      if (transporter) {
        const link = `${BASE_URL}/api/verify-email?token=${token}`;
        const html = (await getEmailTemplate('verification')).replace(/\[VERIFICATION_LINK\]/g, link);
        await transporter.sendMail({
          from: process.env.APP_E,
          to: email,
          subject: 'Verify Your HostNet Account',
          html
        });
      }

      await session.commitTransaction();
      session.endSession();

      const jwtToken = generateJWT({ username });
      return res.json({ token: jwtToken, username, verified: false });

    } catch (err) {
      await session.abortTransaction();
      console.error('Registration failed:', err.message);
      return res.status(500).json({ error: 'Internal error' });
    }
  }
);

// GET /api/verify-email
app.get('/api/verify-email', query('token').isUUID(), async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).send('<h1>Invalid Link</h1>');

  const { token } = req.query;
  const user = await User.findOne({ verificationToken: token });
  if (!user) return res.status(400).send('<h1>Invalid or expired link.</h1>');
  if (user.verificationExpiry < new Date()) return res.status(400).send('<h1>Link expired.</h1>');

  user.verified = true;
  user.verificationToken = undefined;
  user.verificationExpiry = undefined;
  await user.save();

  res.redirect('/verified.html');
});

// POST /api/login
app.post('/api/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing credentials' });

  // Fake delay to prevent timing attacks
  const user = await User.findOne({ email }).select('+password_hash');
  if (!user) {
    await bcrypt.hash('fake', 10);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid || !user.verified) return res.status(401).json({ error: 'Invalid or unverified' });

  const token = generateJWT({ username: user.username });
  res.json({ token, username: user.username, verified: true });
});

// GET /api/user/:id → Secure View Tracking
app.get('/api/user/:id', param('id').trim().escape(), async (req, res) => {
  const { id } = req.params;

  const profile = await Profile.findOne({ username: id }).select('-_id -__v');
  if (!profile) return res.status(404).json({ error: 'User not found' });

  const today = new Date().toISOString().split('T')[0];

  // Get real IP (behind proxies)
  const ip = (req.headers['x-forwarded-for'] || req.ip || '127.0.0.1').split(',')[0].trim();
  const ipHash = hashIP(ip);

  let view = await View.findOne({ username: id });

  if (!view) {
    view = new View({ username: id, daily: {}, ipHashes: {} });
  }

  // Only count if not viewed today
  const lastViewDate = view.ipHashes[ipHash];
  if (!lastViewDate || new Date(lastViewDate).toISOString().split('T')[0] !== today) {
    view.total += 1;
    view.daily.set(today, (view.daily.get(today) || 0) + 1);
    view.ipHashes.set(ipHash, new Date());
    await view.save().catch(console.error);
  }

  res.json({
    name: profile.name,
    avatar: profile.avatar,
    banner: profile.banner,
    bio: profile.bio,
    links: profile.links,
    theme: profile.theme,
    videoUrl: profile.videoUrl,
    videoPosition: profile.videoPosition
  });
});

// GET /api/dashboard/:username
app.get('/api/dashboard/:username', async (req, res) => {
  const { username } = req.params;
  const profile = await Profile.findOne({ username });
  if (!profile) return res.status(404).json({ error: 'User not found' });

  const view = await View.findOne({ username }) || { total: 0, daily: new Map(), ipHashes: new Map() };
  const totalViews = view.total;
  const dailyViews = Object.fromEntries(view.daily);
  const uniqueVisitors = view.ipHashes.size;

  const oneWeekAgo = new Date(Date.now() - 7 * 86400000).toISOString().split('T')[0];
  const weeklyViews = Object.entries(dailyViews)
    .filter(([date]) => date >= oneWeekAgo)
    .reduce((sum, [, count]) => sum + count, 0);

  const clicks = await Click.find({ username });
  const totalClicks = clicks.reduce((sum, c) => sum + c.count, 0);
  const clicksThisWeek = clicks
    .filter(c => new Date(c.updatedAt) >= new Date(Date.now() - 7 * 86400000))
    .reduce((sum, c) => sum + c.count, 0);

  const topLinks = clicks
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)
    .map(c => ({ title: c.url.split('/').pop() || 'Link', url: c.url, clicks: c.count }));

  const timeline = Object.entries(dailyViews)
    .map(([date, count]) => ({ date, count }))
    .sort((a, b) => new Date(a.date) - new Date(b.date));

  res.json({
    stats: { totalViews, uniqueVisitors, viewsThisWeek: weeklyViews, totalClicks, clicksThisWeek },
    topLinks,
    timeline
  });
});

// GET /api/users
app.get('/api/users', async (req, res) => {
  const profiles = await Profile.find({}, 'username name avatar bio');
  res.json({ users: profiles, total: profiles.length });
});

// POST /api/user/:id (Update)
app.post('/api/user/:id', param('id').trim(), async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const decoded = verifyJWT(token);
  if (!decoded || decoded.username !== req.params.id) return res.status(401).json({ error: 'Forbidden' });

  const profile = await Profile.findOne({ username: decoded.username });
  if (!profile) return res.status(404).json({ error: 'Profile not found' });

  const { name, avatar, bio, links, theme, videoUrl, videoPosition } = req.body;

  if (name && name.length <= 50) profile.name = name;
  if (avatar && /^https?:\/\//i.test(avatar)) profile.avatar = avatar;
  if (bio && bio.length <= 500) profile.bio = bio;
  if (Array.isArray(links)) profile.links = links.slice(0, 5).map(l => ({
    url: String(l.url).substring(0, 200),
    title: String(l.title).substring(0, 50)
  }));
  if (['light', 'dark'].includes(theme)) profile.theme = theme;
  if (videoUrl && /^https?:\/\//i.test(videoUrl)) profile.videoUrl = videoUrl;
  if (videoPosition?.top >= 0 && videoPosition?.top <= 100 && videoPosition?.left >= 0 && videoPosition?.left <= 100) {
    profile.videoPosition = videoPosition;
  }

  await profile.save();
  res.json({ username: decoded.username });
});

// GET /api/redirect/:user/:url
app.get('/api/redirect/:user/:url', async (req, res) => {
  const { user, url } = req.params;
  const decodedUrl = decodeURIComponent(url);

  if (!/^https?:\/\//i.test(decodedUrl)) return res.redirect(302, '/');

  try {
    const click = await Click.findOne({ username: user, url: decodedUrl }) || new Click({ username: user, url: decodedUrl });
    click.count++;
    await click.save();
  } catch (e) { /* ignore tracking error */ }

  res.redirect(302, decodedUrl);
});

// POST /api/resend-verification
app.post('/api/resend-verification', emailLimiter, async (req, res) => {
  const { email } = req.body;
  if (!validateEmail(email)) return res.status(400).json({ error: 'Invalid email' });

  const user = await User.findOne({ email, verified: false });
  if (!user) return res.json({ message: 'If registered, a link was sent.' });

  user.verificationToken = uuidv4();
  user.verificationExpiry = new Date(Date.now() + 24 * 3600000);
  await user.save();

  if (transporter) {
    const link = `${BASE_URL}/api/verify-email?token=${user.verificationToken}`;
    const html = (await getEmailTemplate('verification')).replace(/\[VERIFICATION_LINK\]/g, link);
    await transporter.sendMail({
      from: process.env.APP_E,
      to: email,
      subject: 'Resend: Verify Your Email',
      html
    });
  }

  res.json({ message: 'Verification link resent.' });
});

// Health Check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', uptime: process.uptime() });
});

// === Auto-Cleanup of Unverified Accounts ===
async function cleanupUnverifiedAccounts() {
  try {
    const now = new Date();
    const cutoff = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    const unverifiedUsers = await User.find({
      verified: false,
      createdAt: { $lt: cutoff }
    });

    for (const user of unverifiedUsers) {
      try {
        if (transporter) {
          const template = await getEmailTemplate('warning');
          const link = `${BASE_URL}/api/verify-email?token=${user.verificationToken}`;
          const html = template.replace(/\[VERIFICATION_LINK\]/g, link);
          await transporter.sendMail({
            from: process.env.APP_E,
            to: user.email,
            subject: 'Account Deletion Warning',
            html
          });
          console.log(`Warning sent to: ${user.email}`);
        }

        // Schedule deletion in 24h
        setTimeout(async () => {
          const u = await User.findOne({ email: user.email, verified: false });
          if (u) {
            await User.deleteOne({ email: u.email });
            await Profile.deleteOne({ username: u.username });
            console.log(`Deleted unverified account: ${u.email}`);
          }
        }, 24 * 60 * 60 * 1000);

      } catch (err) {
        console.error('Cleanup warning failed:', err);
      }
    }
  } catch (err) {
    console.error('Cleanup error:', err);
  }
}

// === Start Server ===
app.listen(PORT, () => {
  console.log(`🔒 HostNet API running securely on port ${PORT}`);
  cleanupUnverifiedAccounts();
  setInterval(cleanupUnverifiedAccounts, 24 * 60 * 60 * 1000);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('👋 Shutting down gracefully...');
  await mongoose.connection.close();
  process.exit(0);
});
