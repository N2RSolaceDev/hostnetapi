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

// Base URL for email links
const BASE_URL = process.env.BASE_URL || 'https://hostnetapi.onrender.com';

// Middleware
app.use(express.json());
app.use(cors({
  origin: ['https://hostnet.wiki', 'https://www.hostnet.wiki'],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
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

// Email transporter setup
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
    // Verify email configuration
    transporter.verify((error, success) => {
      if (error) {
        console.error('Email configuration error:', error);
      } else {
        console.log('Email server is ready to send messages');
      }
    });
  } else {
    console.warn('Email configuration missing - APP_E and APP_P environment variables required');
  }
} catch (error) {
  console.error('Failed to create email transporter:', error.message);
}

// Data directory
const DATA_DIR = './data';
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PROFILES_FILE = path.join(DATA_DIR, 'profiles.json');
const EMAILS_FILE = path.join(DATA_DIR, 'emails.json');
const USERNAME_HISTORY_FILE = path.join(DATA_DIR, 'username_history.json');
const CLICKS_FILE = path.join(DATA_DIR, 'clicks.json');
const RATE_LIMITS_FILE = path.join(DATA_DIR, 'rate_limits.json');
const VIEWS_FILE = path.join(DATA_DIR, 'views.json');

// Ensure data directory exists
async function ensureDataDirectory() {
  try {
    await fs.access(DATA_DIR);
  } catch {
    await fs.mkdir(DATA_DIR, { recursive: true });
  }
}

// Initialize data files with defaults
async function initializeDataFiles() {
  try {
    const files = [
      USERS_FILE,
      PROFILES_FILE,
      EMAILS_FILE,
      USERNAME_HISTORY_FILE,
      CLICKS_FILE,
      RATE_LIMITS_FILE,
      VIEWS_FILE
    ];
    for (const filePath of files) {
      try {
        await fs.access(filePath);
      } catch {
        await fs.writeFile(filePath, '{}');
      }
    }
  } catch (err) {
    console.error('Error initializing data files:', err);
  }
}

// Helper functions
async function readJSONFile(filePath) {
  try {
    const data = await fs.readFile(filePath, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    return {};
  }
}

async function writeJSONFile(filePath, data) {
  try {
    await fs.writeFile(filePath, JSON.stringify(data, null, 2));
    return true;
  } catch (err) {
    console.error(`Error writing to ${filePath}:`, err);
    return false;
  }
}

async function atomicWrite(filePath, data) {
  const tempPath = `${filePath}.tmp`;
  try {
    await fs.writeFile(tempPath, JSON.stringify(data, null, 2));
    await fs.rename(tempPath, filePath);
    return true;
  } catch (err) {
    console.error(`Atomic write failed for ${filePath}:`, err);
    try {
      await fs.unlink(tempPath);
    } catch { }
    return false;
  }
}

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

// Generate verification token
function generateVerificationToken() {
  return uuidv4();
}

// Read email template
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
    let processed = template
      .replace(/\[TEMPLATE_TYPE\]/g, templateType)
      .replace(/\[TITLE\]/g, values.TITLE || '')
      .replace(/\[SUBJECT\]/g, values.SUBJECT || '')
      .replace(/\[MESSAGE\]/g, values.MESSAGE || '')
      .replace(/\[BUTTON_TEXT\]/g, values.BUTTON_TEXT || '')
      .replace(/\[EXPIRY_TIME\]/g, values.EXPIRY_TIME || '');
    return processed;
  } catch (err) {
    console.error('Error reading email template:', err);
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; background-color: #f5f5f5; }
          .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; }
          .header { background-color: #6366f1; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
          .content { padding: 20px; }
          .button { display: inline-block; padding: 12px 24px; background-color: #6366f1; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
          .footer { padding: 20px; text-align: center; color: #888; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>[TITLE]</h1>
          </div>
          <div class="content">
            <p>Hello,</p>
            <p>[MESSAGE]</p>
            <a href="[VERIFICATION_LINK]" class="button">[BUTTON_TEXT]</a>
            <p>If the button doesn't work, copy and paste this link in your browser:</p>
            <p><a href="[VERIFICATION_LINK]">[VERIFICATION_LINK]</a></p>
            <p>This link will expire in [EXPIRY_TIME].</p>
          </div>
          <div class="footer">
            <p>&copy; 2023 HostNet. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }
}

// Validation helpers
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

// Scheduled cleanup task for unverified accounts
async function cleanupUnverifiedAccounts() {
  try {
    const now = new Date();
    const cutoffDate = new Date(now.getTime() - 24 * 60 * 60 * 1000); // 24 hours ago
    const unverifiedUsers = await User.find({
      verified: false,
      createdAt: { $lt: cutoffDate }
    });
    for (const user of unverifiedUsers) {
      try {
        if (transporter) {
          const template = await getEmailTemplate('warning');
          const verificationLink = `${BASE_URL}/api/verify-email?token=${user.verificationToken}`;
          const emailContent = template.replace(/\[VERIFICATION_LINK\]/g, verificationLink);
          const mailOptions = {
            from: process.env.APP_E,
            to: user.email,
            subject: 'Important: Your Account Will Be Deleted',
            html: emailContent
          };
          await transporter.sendMail(mailOptions);
          console.log(`Warning email sent to unverified user: ${user.email}`);
        }
        // Schedule deletion after another 24 hours
        setTimeout(async () => {
          await deleteAccount(user.email);
        }, 24 * 60 * 60 * 1000); // 24 hours
      } catch (emailErr) {
        console.error('Failed to send warning email:', emailErr);
      }
    }
  } catch (err) {
    console.error('Cleanup error:', err);
  }
}

// Delete account function
async function deleteAccount(email) {
  try {
    const user = await User.findOne({ email });
    if (!user) return;
    if (transporter) {
      const template = await getEmailTemplate('deleted');
      const emailContent = template.replace(/\[VERIFICATION_LINK\]/g, `${BASE_URL}/api/register`);
      const mailOptions = {
        from: process.env.APP_E,
        to: email,
        subject: 'Your Account Has Been Deleted',
        html: emailContent
      };
      await transporter.sendMail(mailOptions);
      console.log(`Deleted email sent to: ${email}`);
    }
    await User.deleteOne({ email });
    await Profile.deleteOne({ username: user.username });
    await Email.deleteOne({ email });
    await UsernameHistory.deleteOne({ username: user.username });
    console.log(`Account deleted for email: ${email}`);
  } catch (err) {
    console.error('Account deletion error:', err);
  }
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
  customCSS: { type: String, default: '' }
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

// Routes

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const usernameError = validateUsername(username);
    const emailError = validateEmail(email);
    const passwordError = validatePassword(password);
    if (usernameError) return res.status(400).json({ error: usernameError });
    if (emailError) return res.status(400).json({ error: emailError });
    if (passwordError) return res.status(400).json({ error: passwordError });
    const existingEmail = await Email.findOne({ email });
    if (existingEmail) return res.status(400).json({ error: 'Email already registered' });
    const usernameHistory = await UsernameHistory.findOne({ username });
    if (usernameHistory) {
      const lastUsed = new Date(usernameHistory.lastUsed);
      const now = new Date();
      const diffDays = Math.floor((now - lastUsed) / (1000 * 60 * 60 * 24));
      if (diffDays < 7) return res.status(400).json({ error: 'Username is on cooldown' });
    }
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ error: 'Username already taken' });
    const hashedPassword = await bcrypt.hash(password, 12);
    const verificationToken = generateVerificationToken();
    const verificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
    const newUser = new User({
      username,
      email,
      password_hash: hashedPassword,
      verificationToken,
      verificationExpiry
    });
    await newUser.save();
    await new Profile({
      username,
      name: username,
      avatar: '',
      banner: '',
      bio: '',
      links: [],
      theme: 'light',
      customCSS: ''
    }).save();
    await new Email({ email, username }).save();
    // Send verification email
    if (transporter) {
      try {
        const verificationLink = `${BASE_URL}/api/verify-email?token=${verificationToken}`;
        const template = await getEmailTemplate('verification');
        const emailContent = template.replace(/\[VERIFICATION_LINK\]/g, verificationLink);
        const mailOptions = {
          from: process.env.APP_E,
          to: email,
          subject: 'Verify Your HostNet Account',
          html: emailContent
        };
        await transporter.sendMail(mailOptions);
        console.log('Verification email sent');
      } catch (err) {
        console.error('Failed to send verification email:', err);
      }
    }
    const token = generateJWT({ username, iss: 'hostnet', aud: 'hostnet-users' });
    res.json({ token, username, verified: false });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify Email
app.get('/api/verify-email', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: 'Verification token is required' });
    const user = await User.findOne({ verificationToken: token });
    if (!user) return res.status(400).json({ error: 'Invalid or expired token' });
    if (user.verificationExpiry < new Date()) {
      return res.status(400).json({ error: 'Verification token has expired' });
    }
    user.verified = true;
    user.verificationToken = undefined;
    user.verificationExpiry = undefined;
    await user.save();
    res.json({ message: 'Email verified successfully', verified: true });
  } catch (err) {
    console.error('Email verification error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const emailError = validateEmail(email);
    const passwordError = validatePassword(password);
    if (emailError) return res.status(400).json({ error: emailError });
    if (passwordError) return res.status(400).json({ error: passwordError });
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (!user.verified) return res.status(401).json({ error: 'Please verify your email first' });
    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = generateJWT({ username: user.username });
    res.json({ token, username: user.username, verified: user.verified });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get User Profile
app.get('/api/user/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const profile = await Profile.findOne({ username: id });
    if (!profile) return res.status(404).json({ error: 'User not found' });
    try {
      let viewRecord = await View.findOne({ username: id }) || new View({ username: id, total: 0, daily: {}, ipTracking: {} });
      const ip = req.ip || 'unknown';
      const today = new Date().toISOString().split('T')[0];
      if (!viewRecord.daily[today]) viewRecord.daily[today] = 0;
      if (!viewRecord.ipTracking[ip]) {
        viewRecord.total += 1;
        viewRecord.daily[today] += 1;
        viewRecord.ipTracking[ip] = today;
        await viewRecord.save();
      }
    } catch (err) {
      console.error('View tracking failed:', err);
    }
    res.json({
      name: profile.name,
      avatar: profile.avatar,
      banner: profile.banner,
      bio: profile.bio,
      links: profile.links,
      theme: profile.theme
    });
  } catch (err) {
    console.error('Get profile error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get All Users
app.get('/api/users', async (req, res) => {
  try {
    const profiles = await Profile.find({}, 'username name avatar banner bio links theme');
    res.json({
      users: profiles.map(p => p.toObject()),
      total: profiles.length
    });
  } catch (err) {
    console.error('Get all users error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update Profile
app.post('/api/user/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    const decoded = verifyJWT(token);
    if (!decoded || decoded.username !== id) return res.status(401).json({ error: 'Unauthorized' });
    const { name, avatar, banner, bio, links, newUsername, theme, customCSS } = req.body;
    const user = await User.findOne({ username: id });
    if (!user) return res.status(404).json({ error: 'User not found' });
    let updatedUsername = id;
    if (newUsername && newUsername !== id) {
      if (validateUsername(newUsername)) return res.status(400).json({ error: validateUsername(newUsername) });
      const history = await UsernameHistory.findOne({ username: newUsername });
      if (history && (Date.now() - new Date(history.lastUsed)) / (1000 * 60 * 60 * 24) < 7) {
        return res.status(400).json({ error: 'Username is on cooldown' });
      }
      if (await User.findOne({ username: newUsername })) return res.status(400).json({ error: 'Username already taken' });
      user.username = newUsername;
      await user.save();
      await Email.findOneAndUpdate({ username: id }, { username: newUsername });
      await Profile.findOneAndUpdate({ username: id }, { username: newUsername });
      await new UsernameHistory({ username: id, lastUsed: new Date() }).save();
      updatedUsername = newUsername;
    }
    const profile = await Profile.findOne({ username: updatedUsername });
    if (profile) {
      profile.name = name ?? profile.name;
      profile.avatar = avatar ?? profile.avatar;
      profile.banner = banner ?? profile.banner;
      profile.bio = bio ?? profile.bio;
      profile.links = links ?? profile.links;
      profile.theme = theme ?? profile.theme;
      profile.customCSS = customCSS ?? profile.customCSS;
      await profile.save();
    }
    const newToken = updatedUsername !== id ? generateJWT({ username: updatedUsername }) : token;
    res.json({ token: newToken, username: updatedUsername });
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Redirect
app.get('/api/redirect/:user/:url', async (req, res) => {
  try {
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
  } catch (err) {
    console.error('Redirect error:', err);
    res.redirect(302, '/');
  }
});

// Resend Verification Email
app.post('/api/resend-verification', async (req, res) => {
  try {
    const { email } = req.body;

    // Validate email
    const emailError = validateEmail(email);
    if (emailError) return res.status(400).json({ error: emailError });

    // Find the user
    const user = await User.findOne({ email });
    if (!user) {
      // Generic message to prevent email enumeration
      return res.json({ message: 'If your email is registered and unverified, a new verification link has been sent.' });
    }

    // Check if already verified
    if (user.verified) {
      return res.json({ message: 'This email is already verified.' });
    }

    // Generate new token and expiry
    const newVerificationToken = generateVerificationToken();
    const newVerificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Update user
    user.verificationToken = newVerificationToken;
    user.verificationExpiry = newVerificationExpiry;
    await user.save();

    // Send email
    if (transporter) {
      try {
        const verificationLink = `${BASE_URL}/api/verify-email?token=${newVerificationToken}`;
        const template = await getEmailTemplate('verification');
        const emailContent = template.replace(/\[VERIFICATION_LINK\]/g, verificationLink);
        const mailOptions = {
          from: process.env.APP_E,
          to: email,
          subject: 'Verify Your HostNet Account',
          html: emailContent
        };
        await transporter.sendMail(mailOptions);
        console.log(`Resent verification email to: ${email}`);
      } catch (err) {
        console.error('Failed to resend verification email:', err);
        return res.status(500).json({ error: 'Failed to send email. Please try again later.' });
      }
    }

    res.json({ message: 'A new verification link has been sent to your email.' });

  } catch (err) {
    console.error('Resend verification error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down gracefully...');
  await mongoose.connection.close();
  process.exit(0);
});

// Start server
async function startServer() {
  await ensureDataDirectory();
  await initializeDataFiles();
  app.listen(PORT, () => {
    console.log(`HostNet API server running on port ${PORT}`);
    cleanupUnverifiedAccounts();
    setInterval(cleanupUnverifiedAccounts, 24 * 60 * 60 * 1000); // every 24h
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
