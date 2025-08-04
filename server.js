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

// Connect to MongoDB using environment variable
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
const VIEWS_FILE = path.join(DATA_DIR, 'views.json'); // New file for view tracking

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

    // Find unverified accounts older than 24 hours
    const unverifiedUsers = await User.find({
      verified: false,
      createdAt: { $lt: cutoffDate }
    });

    for (const user of unverifiedUsers) {
      try {
        if (transporter) {
          const template = await getEmailTemplate('warning');
          const verificationLink = `https://hostnet.wiki/verify-email?token=${user.verificationToken}`;
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

        // Delete account after another 24 hours
        setTimeout(async () => {
          await deleteAccount(user.email);
        }, 24 * 60 * 60 * 1000); // 24 hours from now

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
      const emailContent = template.replace(/\[VERIFICATION_LINK\]/g, 'https://hostnet.wiki/sign');
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

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password_hash: { type: String, required: true },
  verified: { type: Boolean, default: false },
  verificationToken: { type: String },
  verificationExpiry: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

// Profile Schema
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

// Email Mapping Schema
const emailSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true }
});

// Username History Schema
const usernameHistorySchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  lastUsed: { type: Date, default: Date.now }
});

// Clicks Schema
const clickSchema = new mongoose.Schema({
  username: { type: String, required: true },
  url: { type: String, required: true },
  count: { type: Number, default: 0 }
});

// View Schema
const viewSchema = new mongoose.Schema({
  username: { type: String, required: true },
  total: { type: Number, default: 0 },
  daily: { type: Map, of: Number, default: {} },
  ipTracking: { type: Map, of: String, default: {} }
});

// Model definitions
const User = mongoose.model('User', userSchema);
const Profile = mongoose.model('Profile', profileSchema);
const Email = mongoose.model('Email', emailSchema);
const UsernameHistory = mongoose.model('UsernameHistory', usernameHistorySchema);
const Click = mongoose.model('Click', clickSchema);
const View = mongoose.model('View', viewSchema);

// Routes

// Register endpoint
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
    if (existingEmail) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const usernameHistory = await UsernameHistory.findOne({ username });
    if (usernameHistory) {
      const lastUsed = new Date(usernameHistory.lastUsed);
      const now = new Date();
      const diffDays = Math.floor((now - lastUsed) / (1000 * 60 * 60 * 24));
      if (diffDays < 7) {
        return res.status(400).json({ error: 'Username is on cooldown' });
      }
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already taken' });
    }

    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

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

    const newProfile = new Profile({
      username,
      name: username,
      avatar: '',
      banner: '',
      bio: '',
      links: [],
      theme: 'light',
      customCSS: ''
    });
    await newProfile.save();

    const newEmail = new Email({ email, username });
    await newEmail.save();

    // Send verification email
    if (transporter) {
      try {
        const verificationLink = `https://hostnet.wiki/verify-email?token=${verificationToken}`;
        const template = await getEmailTemplate('verification');
        const emailContent = template.replace(/\[VERIFICATION_LINK\]/g, verificationLink);

        const mailOptions = {
          from: process.env.APP_E,
          to: email,
          subject: 'Verify Your HostNet Account',
          html: emailContent
        };

        await transporter.sendMail(mailOptions);
        console.log('Verification email sent successfully');
      } catch (emailError) {
        console.error('Failed to send verification email:', emailError);
      }
    }

    const token = generateJWT({ username, iss: 'hostnet', aud: 'hostnet-users' });
    res.json({ token, username, verified: false });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify email endpoint
app.get('/api/verify-email', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) {
      return res.status(400).json({ error: 'Verification token is required' });
    }

    const user = await User.findOne({ verificationToken: token });
    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired verification token' });
    }

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

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const emailError = validateEmail(email);
    const passwordError = validatePassword(password);

    if (emailError) return res.status(400).json({ error: emailError });
    if (passwordError) return res.status(400).json({ error: passwordError });

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!user.verified) {
      return res.status(401).json({ error: 'Please verify your email address first' });
    }

    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = generateJWT({ username: user.username, iss: 'hostnet', aud: 'hostnet-users' });
    res.json({ token, username: user.username, verified: user.verified });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user profile with view counting
app.get('/api/user/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const profile = await Profile.findOne({ username: id });
    if (!profile) {
      return res.status(404).json({ error: 'User not found' });
    }

    try {
      let viewRecord = await View.findOne({ username: id });
      if (!viewRecord) {
        viewRecord = new View({
          username: id,
          total: 0,
          daily: {},
          ipTracking: {}
        });
      }

      const ip = req.ip || 'unknown';
      const today = new Date().toISOString().split('T')[0];

      if (!viewRecord.daily[today]) {
        viewRecord.daily[today] = 0;
      }

      if (!viewRecord.ipTracking[ip]) {
        viewRecord.total += 1;
        viewRecord.daily[today] += 1;
        viewRecord.ipTracking[ip] = today;
        await viewRecord.save();
      }
    } catch (err) {
      console.error('View tracking failed:', err);
    }

    const publicProfile = {
      name: profile.name,
      avatar: profile.avatar,
      banner: profile.banner,
      bio: profile.bio,
      links: profile.links,
      theme: profile.theme
    };

    res.json(publicProfile);
  } catch (err) {
    console.error('Get user profile error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get list of all user profiles
app.get('/api/users', async (req, res) => {
  try {
    const profiles = await Profile.find({}, {
      username: 1,
      name: 1,
      avatar: 1,
      banner: 1,
      bio: 1,
      links: 1,
      theme: 1
    });

    const usersList = profiles.map(profile => ({
      username: profile.username,
      name: profile.name,
      avatar: profile.avatar,
      banner: profile.banner,
      bio: profile.bio,
      links: profile.links,
      theme: profile.theme
    }));

    res.json({ users: usersList, total: usersList.length });
  } catch (err) {
    console.error('Get all users error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update user profile
app.post('/api/user/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    const decoded = verifyJWT(token);
    if (!decoded || decoded.username !== id) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { name, avatar, banner, bio, links, newUsername, theme, customCSS } = req.body;

    const user = await User.findOne({ username: id });
    if (!user) return res.status(404).json({ error: 'User not found' });

    let updatedUsername = id;
    if (newUsername && newUsername !== id) {
      const usernameError = validateUsername(newUsername);
      if (usernameError) return res.status(400).json({ error: usernameError });

      const history = await UsernameHistory.findOne({ username: newUsername });
      if (history) {
        const lastUsed = new Date(history.lastUsed);
        const now = new Date();
        const diffDays = Math.floor((now - lastUsed) / (1000 * 60 * 60 * 24));
        if (diffDays < 7) return res.status(400).json({ error: 'Username is on cooldown' });
      }

      const existingUser = await User.findOne({ username: newUsername });
      if (existingUser) return res.status(400).json({ error: 'Username already taken' });

      updatedUsername = newUsername;
      user.username = newUsername;
      await user.save();

      const emailDoc = await Email.findOne({ username: id });
      if (emailDoc) {
        emailDoc.username = newUsername;
        await emailDoc.save();
      }

      const profile = await Profile.findOne({ username: id });
      if (profile) {
        profile.username = newUsername;
        await profile.save();
      }

      const historyEntry = new UsernameHistory({
        username: id,
        lastUsed: new Date()
      });
      await historyEntry.save();
    }

    const profile = await Profile.findOne({ username: updatedUsername });
    if (profile) {
      if (name !== undefined) profile.name = name;
      if (avatar !== undefined) profile.avatar = avatar;
      if (banner !== undefined) profile.banner = banner;
      if (bio !== undefined) profile.bio = bio;
      if (links !== undefined) profile.links = links;
      if (theme !== undefined) profile.theme = theme;
      if (customCSS !== undefined) profile.customCSS = customCSS;
      await profile.save();
    }

    let newToken = token;
    if (updatedUsername !== id) {
      newToken = generateJWT({ username: updatedUsername, iss: 'hostnet', aud: 'hostnet-users' });
    }

    res.json({ token: newToken, username: updatedUsername });
  } catch (err) {
    console.error('Update user profile error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Redirect endpoint
app.get('/api/redirect/:user/:url', async (req, res) => {
  try {
    const { user, url } = req.params;
    const decodedUrl = decodeURIComponent(url);

    try {
      let clickRecord = await Click.findOne({ username: user, url: decodedUrl });
      if (!clickRecord) {
        clickRecord = new Click({ username: user, url: decodedUrl, count: 0 });
      }
      clickRecord.count++;
      await clickRecord.save();
    } catch (err) {
      console.error('Click tracking failed:', err);
    }

    res.redirect(302, decodedUrl);
  } catch (err) {
    console.error('Redirect error:', err);
    res.redirect(302, '/');
  }
});

// Health check endpoint
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
    setInterval(cleanupUnverifiedAccounts, 24 * 60 * 60 * 1000); // Run every 24 hours
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
