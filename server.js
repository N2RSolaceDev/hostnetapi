// server.js
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

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || 'https://hostnetapi.onrender.com';

app.use(express.static(path.join(__dirname)));
app.use(express.json());
app.use(cors({
  origin: ['https://hostnet.wiki', 'https://www.hostnet.wiki'],
  credentials: true
}));

// Global rate limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP'
});
app.use(limiter);

// Connect to MongoDB
const MONGO_URI = process.env.MONGO_URI;
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// Email transporter
let transporter = null;
try {
  if (process.env.APP_E && process.env.APP_P) {
    transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.APP_E,
        pass: process.env.APP_P
      }
    });
    transporter.verify((error, success) => {
      if (error) console.error('Email config error:', error);
      else console.log('Email server ready');
    });
  } else {
    console.warn('Email config missing - APP_E and APP_P required');
  }
} catch (error) {
  console.error('Failed to create transporter:', error.message);
}

// Schemas
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password_hash: { type: String, required: true },
  verified: { type: Boolean, default: false },
  verificationToken: { type: String },
  verificationExpiry: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

const profileSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  name: { type: String, default: '' },
  avatar: { type: String, default: '' },
  banner: { type: String, default: '' },
  bio: { type: String, default: '' },
  links: { type: Array, default: [] },
  theme: { type: String, default: 'light' },
  customCSS: { type: String, default: '' },
  badges: { type: Array, default: [] },
  videoUrl: { type: String, default: '' },
  videoPosition: {
    top: { type: Number, default: 50 },
    left: { type: Number, default: 50 }
  }
});

const emailSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true }
});

const usernameHistorySchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  lastUsed: { type: Date, default: Date.now }
});

const clickSchema = new mongoose.Schema({
  username: { type: String, required: true },
  url: { type: String, required: true },
  count: { type: Number, default: 0 }
});

const viewSchema = new mongoose.Schema({
  username: { type: String, required: true },
  total: { type: Number, default: 0 },
  daily: { type: Map, of: Number, default: {} },
  ipTracking: { type: Map, of: String, default: {} }
});

// Models
const User = mongoose.model('User', userSchema);
const Profile = mongoose.model('Profile', profileSchema);
const Email = mongoose.model('Email', emailSchema);
const UsernameHistory = mongoose.model('UsernameHistory', usernameHistorySchema);
const Click = mongoose.model('Click', clickSchema);
const View = mongoose.model('View', viewSchema);

// Helper Functions
function generateJWT(payload) {
  const secret = process.env.JWT_SECRET || 'default_secret_key';
  return jwt.sign(payload, secret, { expiresIn: '24h' });
}

function verifyJWT(token) {
  const secret = process.env.JWT_SECRET || 'default_secret_key';
  try {
    return jwt.verify(token, secret);
  } catch (err) {
    return null;
  }
}

function generateVerificationToken() {
  return uuidv4();
}

function validateUsername(username) {
  if (!username || username.length < 3 || username.length > 20) {
    return 'Username must be between 3 and 20 characters';
  }
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return 'Username can only contain letters, numbers, and underscores';
  }
  return null;
}

function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRegex.test(email)) {
    return 'Invalid email format';
  }
  return null;
}

function validatePassword(password) {
  if (!password || password.length < 6) {
    return 'Password must be at least 6 characters';
  }
  return null;
}

async function getEmailTemplate(templateType) {
  try {
    const templatePath = path.join(__dirname, 'email.html');
    const template = await fs.readFile(templatePath, 'utf8');
    const replacements = {
      verification: {
        TITLE: 'Verify Your HostNet Account',
        SUBJECT: 'Verify Your HostNet Account',
        MESSAGE: 'Thank you for signing up with HostNet! Please verify your email address by clicking the button below:',
        BUTTON_TEXT: 'Verify Email',
        EXPIRY_TIME: '24 hours'
      },
      warning: {
        TITLE: 'Important: Your Account Will Be Deleted',
        SUBJECT: 'Important: Your Account Will Be Deleted',
        MESSAGE: 'We noticed that your email has not been verified within 24 hours. Your account will be deleted in 24 hours unless you verify your email.',
        BUTTON_TEXT: 'Verify Now',
        EXPIRY_TIME: '24 hours'
      },
      deleted: {
        TITLE: 'Your Account Has Been Deleted',
        SUBJECT: 'Your Account Has Been Deleted',
        MESSAGE: 'Your HostNet account has been deleted due to unverified email. You can create a new account anytime.',
        BUTTON_TEXT: 'Create New Account',
        EXPIRY_TIME: 'n/a'
      }
    };
    const values = replacements[templateType] || {};
    return template
      .replace(/\[TEMPLATE_TYPE\]/g, templateType)
      .replace(/\[TITLE\]/g, values.TITLE || '')
      .replace(/\[SUBJECT\]/g, values.SUBJECT || '')
      .replace(/\[MESSAGE\]/g, values.MESSAGE || '')
      .replace(/\[BUTTON_TEXT\]/g, values.BUTTON_TEXT || '')
      .replace(/\[EXPIRY_TIME\]/g, values.EXPIRY_TIME || '');
  } catch (err) {
    console.error('Error reading email template:', err);
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; background-color: #f5f5f5; }
          .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; }
          .header { background-color: #6366f1; color: white; padding: 20px; text-align: center; }
          .button { display: inline-block; padding: 12px 24px; background-color: #6366f1; color: white; text-decoration: none; border-radius: 4px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header"><h1>[TITLE]</h1></div>
          <p>[MESSAGE]</p>
          <a href="[VERIFICATION_LINK]" class="button">[BUTTON_TEXT]</a>
          <p>This link expires in [EXPIRY_TIME].</p>
        </div>
      </body>
      </html>
    `;
  }
}

async function getDeletionTemplate() {
  try {
    const templatePath = path.join(__dirname, 'email-delete.html');
    let template = await fs.readFile(templatePath, 'utf8');
    return template;
  } catch (err) {
    console.error('Error reading deletion email template:', err);
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; background-color: #f5f5f5; }
          .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; }
          .header { background-color: #e53e3e; color: white; padding: 20px; text-align: center; }
          .button { display: inline-block; padding: 12px 24px; background-color: #e53e3e; color: white; text-decoration: none; border-radius: 4px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header"><h1>Confirm Account Deletion</h1></div>
          <p>You requested to delete your account. This action is <strong style="color: #e53e3e;">permanent and cannot be undone</strong>.</p>
          <a href="[DELETE_CONFIRM_LINK]" class="button">Delete My Account</a>
          <p>This link will expire in 1 hour.</p>
          <p>If you did not request this, ignore this email.</p>
        </div>
      </body>
      </html>
    `;
  }
}

async function cleanupUnverifiedAccounts() {
  try {
    const now = new Date();
    const cutoffDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const unverifiedUsers = await User.find({ verified: false, createdAt: { $lt: cutoffDate } });

    for (const user of unverifiedUsers) {
      try {
        if (transporter) {
          const template = await getEmailTemplate('warning');
          const verificationLink = `${BASE_URL}/api/verify-email?token=${user.verificationToken}`;
          const emailContent = template.replace(/\[VERIFICATION_LINK\]/g, verificationLink);
          await transporter.sendMail({
            from: process.env.APP_E,
            to: user.email,
            subject: 'Important: Your Account Will Be Deleted',
            html: emailContent
          });
          console.log(`Warning sent to unverified user: ${user.email}`);
        }

        setTimeout(async () => {
          await deleteAccount(user.email);
        }, 24 * 60 * 60 * 1000);
      } catch (err) {
        console.error('Failed to send warning:', err);
      }
    }
  } catch (err) {
    console.error('Cleanup error:', err);
  }
}

async function deleteAccount(email) {
  try {
    const user = await User.findOne({ email });
    if (!user) return;

    if (transporter) {
      const template = await getEmailTemplate('deleted');
      const emailContent = template.replace(/\[VERIFICATION_LINK\]/g, `${BASE_URL}/api/register`);
      await transporter.sendMail({
        from: process.env.APP_E,
        to: email,
        subject: 'Your Account Has Been Deleted',
        html: emailContent
      });
      console.log(`Account deleted email sent to: ${email}`);
    }

    await User.deleteOne({ email });
    await Profile.deleteOne({ username: user.username });
    await Email.deleteOne({ email });
    await UsernameHistory.updateOne(
      { username: user.username },
      { $set: { lastUsed: new Date() } },
      { upsert: true }
    );
    await Click.deleteMany({ username: user.username });
    await View.deleteMany({ username: user.username });

    console.log(`Account and all data deleted for: ${email}`);
  } catch (err) {
    console.error('Account deletion error:', err);
  }
}

// ✅ GET /api/users - Full-featured user directory
const usersLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: 'Too many requests to user directory',
  keyGenerator: (req) => req.ip
});

app.use('/api/users', usersLimiter);

app.get('/api/users', async (req, res) => {
  try {
    const { search, limit = 20, offset = 0 } = req.query;

    let query = { verified: true };
    if (search) {
      const regex = new RegExp(search.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      query.username = regex;
    }

    const profiles = await Profile.find(query)
      .select('username name avatar bio badges')
      .sort({ createdAt: -1 })
      .skip(parseInt(offset))
      .limit(parseInt(limit));

    const total = await Profile.countDocuments(query);

    res.json({
      users: profiles,
      total,
      limit: parseInt(limit),
      offset: parseInt(offset)
    });
  } catch (err) {
    console.error('Get users list error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ✅ Register
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const usernameError = validateUsername(username);
    const emailError = validateEmail(email);
    const passwordError = validatePassword(password);
    if (usernameError) return res.status(400).json({ error: usernameError });
    if (emailError) return res.status(400).json({ error: emailError });
    if (passwordError) return res.status(400).json({ error: passwordError });

    if (await Email.findOne({ email })) return res.status(400).json({ error: 'Email already registered' });
    if (await User.findOne({ username })) return res.status(400).json({ error: 'Username already taken' });

    const history = await UsernameHistory.findOne({ username });
    if (history) {
      const diffDays = (Date.now() - new Date(history.lastUsed)) / (1000 * 60 * 60 * 24);
      if (diffDays < 7) return res.status(400).json({ error: 'Username is on cooldown' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const verificationToken = generateVerificationToken();

    const newUser = new User({
      username,
      email,
      password_hash: hashedPassword,
      verificationToken,
      verificationExpiry: new Date(Date.now() + 24 * 60 * 60 * 1000)
    });
    await newUser.save();

    await Profile.create({
      username,
      name: username,
      avatar: '',
      bio: '',
      links: [],
      badges: []
    });

    await Email.create({ email, username });

    if (transporter) {
      const link = `${BASE_URL}/api/verify-email?token=${verificationToken}`;
      const emailContent = (await getEmailTemplate('verification')).replace(/\[VERIFICATION_LINK\]/g, link);
      await transporter.sendMail({
        from: process.env.APP_E,
        to: email,
        subject: 'Verify Your HostNet Account',
        html: emailContent
      });
    }

    const token = generateJWT({ username });
    res.json({ token, username, verified: false });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ✅ Verify Email
app.get('/api/verify-email', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send('<h1>Invalid Link</h1>');

  const user = await User.findOne({ verificationToken: token });
  if (!user) return res.status(400).send('<h1>Link Expired or Invalid</h1>');
  if (user.verificationExpiry < new Date()) return res.status(400).send('<h1>Link Expired</h1>');

  user.verified = true;
  user.verificationToken = undefined;
  user.verificationExpiry = undefined;
  await user.save();

  res.redirect('/verified.html');
});

// ✅ Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !await bcrypt.compare(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (!user.verified) return res.status(401).json({ error: 'Please verify your email first' });

  const token = generateJWT({ username: user.username });
  res.json({ token, username: user.username });
});

// ✅ Get User Profile
app.get('/api/user/:id', async (req, res) => {
  const profile = await Profile.findOne({ username: req.params.id });
  if (!profile) return res.status(404).json({ error: 'User not found' });

  // Track view (once per IP per day)
  try {
    const ip = req.ip;
    const today = new Date().toISOString().split('T')[0];
    let view = await View.findOne({ username: req.params.id }) || new View({ username: req.params.id });

    if (!view.daily[today]) view.daily[today] = 0;
    if (!view.ipTracking[ip] || view.ipTracking[ip] !== today) {
      view.total += 1;
      view.daily[today] += 1;
      view.ipTracking[ip] = today;
      await view.save();
    }
  } catch (err) {
    console.error('View tracking error:', err);
  }

  res.json({
    name: profile.name,
    avatar: profile.avatar,
    banner: profile.banner,
    bio: profile.bio,
    links: profile.links,
    theme: profile.theme,
    badges: profile.badges,
    videoUrl: profile.videoUrl,
    videoPosition: profile.videoPosition
  });
});

// ✅ Update Profile
app.post('/api/user/:id', async (req, res) => {
  const { id } = req.params;
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const decoded = verifyJWT(token);
  if (!decoded || decoded.username !== id) return res.status(401).json({ error: 'Unauthorized' });

  const { newUsername, ...updates } = req.body;
  const user = await User.findOne({ username: id });
  if (!user) return res.status(404).json({ error: 'User not found' });

  let finalUsername = id;

  if (newUsername && newUsername !== id) {
    if (validateUsername(newUsername)) return res.status(400).json({ error: validateUsername(newUsername) });
    if (await User.findOne({ username: newUsername })) return res.status(400).json({ error: 'Username taken' });

    const history = await UsernameHistory.findOne({ username: newUsername });
    if (history && (Date.now() - new Date(history.lastUsed)) / (1000 * 60 * 60 * 24) < 7) {
      return res.status(400).json({ error: 'Username on cooldown' });
    }

    user.username = newUsername;
    await user.save();
    await Profile.updateOne({ username: id }, { username: newUsername });
    await Email.updateOne({ username: id }, { username: newUsername });
    await UsernameHistory.findOneAndUpdate(
      { username: id },
      { lastUsed: new Date() },
      { upsert: true }
    );
    finalUsername = newUsername;
  }

  const profile = await Profile.findOne({ username: finalUsername });
  Object.assign(profile, updates);
  await profile.save();

  const newToken = finalUsername !== id ? generateJWT({ username: finalUsername }) : token;
  res.json({ token: newToken, username: finalUsername });
});

// ✅ Redirect & Track Click
app.get('/api/redirect/:user/:url', async (req, res) => {
  const { user, url } = req.params;
  const decodedUrl = decodeURIComponent(url);

  try {
    const click = await Click.findOne({ username: user, url: decodedUrl }) || new Click({ username: user, url: decodedUrl });
    click.count++;
    await click.save();
  } catch (err) {
    console.error('Click tracking failed:', err);
  }

  res.redirect(302, decodedUrl);
});

// ✅ Dashboard Stats
app.get('/api/dashboard/:username', async (req, res) => {
  const { username } = req.params;
  const profile = await Profile.findOne({ username });
  if (!profile) return res.status(404).json({ error: 'User not found' });

  const view = await View.findOne({ username }) || { total: 0, daily: {} };
  const totalViews = view.total;
  const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  const weeklyViews = Object.entries(view.daily)
    .filter(([date]) => new Date(date) >= weekAgo)
    .reduce((sum, [, count]) => sum + count, 0);

  const uniqueVisitors = Object.keys(view.ipTracking || {}).length;

  const clicks = await Click.find({ username });
  const totalClicks = clicks.reduce((sum, c) => sum + c.count, 0);
  const topLinks = clicks
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)
    .map(c => ({ url: c.url, clicks: c.count }));

  res.json({
    stats: { totalViews, uniqueVisitors, weeklyViews, totalClicks },
    topLinks
  });
});

// ✅ Resend Verification
app.post('/api/resend-verification', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user || user.verified) return res.json({ message: 'Verification email sent if applicable.' });

  const newToken = generateVerificationToken();
  user.verificationToken = newToken;
  user.verificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
  await user.save();

  if (transporter) {
    const link = `${BASE_URL}/api/verify-email?token=${newToken}`;
    const html = (await getEmailTemplate('verification')).replace(/\[VERIFICATION_LINK\]/g, link);
    await transporter.sendMail({
      from: process.env.APP_E,
      to: email,
      subject: 'Verify Your HostNet Account',
      html
    });
  }

  res.json({ message: 'Verification link resent.' });
});

// ✅ Initiate Account Deletion
app.post('/api/account/delete', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const user = await User.findOne({ email });
  if (!user) return res.json({ message: 'If your account exists, a deletion link has been sent.' });

  const isValid = await bcrypt.compare(password, user.password_hash);
  if (!isValid) return res.status(401).json({ error: 'Invalid password' });

  const deleteToken = uuidv4();
  user.verificationToken = deleteToken;
  user.verificationExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
  await user.save();

  if (transporter) {
    const confirmLink = `${BASE_URL}/api/account/confirm-delete?token=${deleteToken}`;
    const html = (await getDeletionTemplate()).replace(/\[DELETE_CONFIRM_LINK\]/g, confirmLink);
    await transporter.sendMail({
      from: process.env.APP_E,
      to: email,
      subject: 'Confirm Your Account Deletion',
      html
    });
    console.log(`Deletion confirmation sent to: ${email}`);
  }

  res.json({ message: 'A confirmation link has been sent to your email.' });
});

// ✅ Confirm Account Deletion
app.get('/api/account/confirm-delete', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send('<h1>Invalid Request</h1>');

  const user = await User.findOne({
    verificationToken: token,
    verificationExpiry: { $gt: new Date() }
  });

  if (!user) return res.status(400).send('<h1>Invalid or Expired Link</h1>');

  await deleteAccount(user.email);

  res.send(`
    <h1>Account Deleted</h1>
    <p>Your account has been permanently deleted.</p>
    <p>Thank you for using HostNet.</p>
    <a href="/">Go Home</a>
  `);
});

// ✅ Health Check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down...');
  await mongoose.connection.close();
  process.exit(0);
});

// Start server
async function startServer() {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    cleanupUnverifiedAccounts();
    setInterval(cleanupUnverifiedAccounts, 24 * 60 * 60 * 1000);
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
