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
//fix later lmao
app.use(express.json());
app.use(cors({
  origin: ['https://hostnet.wiki', 'https://www.hostnet.wiki'],
  credentials: true
}));
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
  // ✅ Video Embed
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
// Helper functions
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
async function cleanupUnverifiedAccounts() {
  try {
    const now = new Date();
    const cutoffDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
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
        setTimeout(async () => {
          await deleteAccount(user.email);
        }, 24 * 60 * 60 * 1000);
      } catch (emailErr) {
        console.error('Failed to send warning email:', emailErr);
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
// Routes
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
      customCSS: '',
      badges: [],
      videoUrl: '',
      videoPosition: { top: 50, left: 50 }
    }).save();
    await new Email({ email, username }).save();
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
app.get('/api/verify-email', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) {
      return res.status(400).send(`
        <h1>Verification Failed</h1>
        <p>No verification token provided.</p>
        <a href="/">Go Home</a>
      `);
    }
    const user = await User.findOne({ verificationToken: token });
    if (!user) {
      return res.status(400).send(`
        <h1>Invalid Link</h1>
        <p>The verification link is invalid or has expired.</p>
        <a href="/resend.html">Request a new link</a>
      `);
    }
    if (user.verificationExpiry < new Date()) {
      return res.status(400).send(`
        <h1>Link Expired</h1>
        <p>Your verification link has expired.</p>
        <a href="/resend.html">Click here to resend</a>
      `);
    }
    user.verified = true;
    user.verificationToken = undefined;
    user.verificationExpiry = undefined;
    await user.save();
    console.log(`Email verified for: ${user.email}`);
    res.redirect(302, '/verified.html');
  } catch (err) {
    console.error('Email verification error:', err);
    res.status(500).send(`
      <h1>Server Error</h1>
      <p>Something went wrong. Please try again later.</p>
      <a href="/">Go Home</a>
    `);
  }
});
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
app.get('/api/user/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const profile = await Profile.findOne({ username: id });
    if (!profile) return res.status(404).json({ error: 'User not found' });
    try {
      let viewRecord = await View.findOne({ username: id });
      if (!viewRecord) {
        viewRecord = new View({ username: id, total: 0, daily: {}, ipTracking: {} });
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
  } catch (err) {
    console.error('Get profile error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.get('/api/users', async (req, res) => {
  try {
    const profiles = await Profile.find({}, 'username name avatar banner bio links theme badges');
    res.json({
      users: profiles.map(p => p.toObject()),
      total: profiles.length
    });
  } catch (err) {
    console.error('Get all users error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.post('/api/user/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    const decoded = verifyJWT(token);
    if (!decoded || decoded.username !== id) return res.status(401).json({ error: 'Unauthorized' });
    const { name, avatar, banner, bio, links, newUsername, theme, customCSS, badges, videoUrl, videoPosition } = req.body;
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
      profile.badges = Array.isArray(badges) ? badges : profile.badges;
      profile.videoUrl = videoUrl ?? profile.videoUrl;
      if (videoPosition && typeof videoPosition.top === 'number' && typeof videoPosition.left === 'number') {
        profile.videoPosition.top = videoPosition.top;
        profile.videoPosition.left = videoPosition.left;
      }
      await profile.save();
    }
    const newToken = updatedUsername !== id ? generateJWT({ username: updatedUsername }) : token;
    res.json({ token: newToken, username: updatedUsername });
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
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
app.post('/api/resend-verification', async (req, res) => {
  try {
    const { email } = req.body;
    const emailError = validateEmail(email);
    if (emailError) return res.status(400).json({ error: emailError });
    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ message: 'If your email is registered and unverified, a new verification link has been sent.' });
    }
    if (user.verified) {
      return res.json({ message: 'This email is already verified.' });
    }
    const newVerificationToken = generateVerificationToken();
    const newVerificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
    user.verificationToken = newVerificationToken;
    user.verificationExpiry = newVerificationExpiry;
    await user.save();
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
app.get('/api/dashboard/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const profile = await Profile.findOne({ username });
    if (!profile) return res.status(404).json({ error: 'User not found' });
    const viewRecord = await View.findOne({ username });
    const totalViews = viewRecord?.total || 0;
    const dailyViews = viewRecord?.daily || {};
    const today = new Date().toISOString().split('T')[0];
    const weekAgo = new Date();
    weekAgo.setDate(weekAgo.getDate() - 7);
    const weeklyViews = Object.entries(dailyViews)
      .filter(([date]) => new Date(date) >= weekAgo)
      .reduce((sum, [, count]) => sum + count, 0);
    const uniqueViews = Object.keys(viewRecord?.ipTracking || {}).length;
    const clickRecords = await Click.find({ username });
    const totalClicks = clickRecords.reduce((sum, c) => sum + c.count, 0);
    const clicksThisWeek = clickRecords
      .filter(c => {
        const last7Days = new Date();
        last7Days.setDate(last7Days.getDate() - 7);
        return new Date(c.updatedAt) > last7Days;
      })
      .reduce((sum, c) => sum + c.count, 0);
    const topLinks = clickRecords
      .sort((a, b) => b.count - a.count)
      .slice(0, 5)
      .map(c => ({ title: c.url.split('/').filter(Boolean).pop() || 'Unnamed', url: c.url, clicks: c.count }));
    const timeline = Object.entries(dailyViews)
      .map(([date, count]) => ({ date, count }))
      .sort((a, b) => new Date(a.date) - new Date(b.date));
    res.json({
      stats: {
        totalViews,
        uniqueViews,
        viewsThisWeek: weeklyViews,
        clicksThisWeek,
        totalClicks
      },
      topLinks,
      timeline
    });
  } catch (err) {
    console.error('Dashboard fetch error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// NEW: Account Deletion Route
app.post('/api/delete-account', async (req, res) => {
  try {
    const { password } = req.body;
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    
    const decoded = verifyJWT(token);
    if (!decoded) return res.status(401).json({ error: 'Invalid token' });
    
    const username = decoded.username;
    const user = await User.findOne({ username });
    
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    // Verify password
    if (!password) return res.status(400).json({ error: 'Password is required' });
    
    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) return res.status(401).json({ error: 'Incorrect password' });
    
    // Send deletion confirmation email if configured
    if (transporter) {
      try {
        const template = await getEmailTemplate('deleted');
        const emailContent = template.replace(/\[VERIFICATION_LINK\]/g, `${BASE_URL}/api/register`);
        const mailOptions = {
          from: process.env.APP_E,
          to: user.email,
          subject: 'Your HostNet Account Has Been Deleted',
          html: emailContent
        };
        await transporter.sendMail(mailOptions);
        console.log(`Deletion confirmation email sent to: ${user.email}`);
      } catch (err) {
        console.error('Failed to send deletion email:', err);
      }
    }
    
    // Delete all associated data
    await User.deleteOne({ username });
    await Profile.deleteOne({ username });
    await Email.deleteOne({ email: user.email });
    await UsernameHistory.deleteOne({ username });
    await Click.deleteMany({ username });
    await View.deleteOne({ username });
    
    console.log(`Account deleted for user: ${username}`);
    
    // Clear authentication data
    res.json({ 
      success: true, 
      message: 'Account deleted successfully' 
    });
    
  } catch (err) {
    console.error('Account deletion error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});
process.on('SIGINT', async () => {
  console.log('Shutting down gracefully...');
  await mongoose.connection.close();
  process.exit(0);
});
async function startServer() {
  app.listen(PORT, () => {
    console.log(`HostNet API server running on port ${PORT}`);
    cleanupUnverifiedAccounts();
    setInterval(cleanupUnverifiedAccounts, 24 * 60 * 60 * 1000);
  });
}
startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
