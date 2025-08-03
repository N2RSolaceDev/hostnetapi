// server.js - HostNet Bio API (Enterprise Edition)
const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const http = require('http').createServer(app);

// ======================
// 🔐 Configuration
// ======================
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error('❌ FATAL: JWT_SECRET is not set in environment variables.');
  process.exit(1);
}

const USERNAME_LOCK_DAYS = 7;
const SALT_ROUNDS = 12;

// ======================
// 🛠️ Utilities
// ======================
class DataStore {
  static async read(filename) {
    const content = await fs.readFile(path.join(DATA_DIR, filename), 'utf8');
    return JSON.parse(content);
  }

  static async write(filename, data) {
    await fs.writeFile(
      path.join(DATA_DIR, filename),
      JSON.stringify(data, null, 2),
      'utf8'
    );
  }
}

// ======================
// 📦 Initialize Data
// ======================
async function initializeDataDir() {
  try {
    await fs.access(DATA_DIR);
  } catch {
    await fs.mkdir(DATA_DIR, { recursive: true });
  }

  const files = {
    'users.json': '{}',
    'profiles.json': '{}',
    'emails.json': '{}',
    'username_history.json': '{}',
    'clicks.json': '{}',
    'templates.json': '{}',
    'rate_limits.json': '{}'
  };

  for (const [filename, content] of Object.entries(files)) {
    const filePath = path.join(DATA_DIR, filename);
    try {
      await fs.access(filePath);
    } catch {
      await fs.writeFile(filePath, content, 'utf8');
      console.log(`✅ Created ${filename}`);
    }
  }
}

// ======================
// 🌐 CORS Setup
// ======================
const ALLOWED_ORIGINS = [
  'https://hostnet.wiki',
  'https://www.hostnet.wiki',
  'http://localhost:5173'
];

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else if (!origin) {
    res.setHeader('Access-Control-Allow-Origin', '*');
  } else {
    return res.status(403).json({ error: 'CORS not allowed' });
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }

  next();
});

app.use(express.json({ limit: '10mb' }));

// ======================
// 🔐 Auth Middleware
// ======================
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ 
      success: false,
      error: 'Authentication required. No token provided.' 
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ 
        success: false,
        error: 'Invalid or expired authentication token.' 
      });
    }
    req.user = user;
    next();
  });
}

// ======================
// 📈 Rate Limiting (Simple)
// ======================
const rateLimits = new Map();

function rateLimit(windowMs = 900000, max = 100) {
  return (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();
    const record = rateLimits.get(ip) || { firstRequest: now, requests: 0 };

    if (now - record.firstRequest > windowMs) {
      rateLimits.set(ip, { firstRequest: now, requests: 1 });
      return next();
    }

    if (record.requests >= max) {
      return res.status(429).json({
        success: false,
        error: 'Too many requests. Please try again later.'
      });
    }

    record.requests++;
    rateLimits.set(ip, record);
    next();
  };
}

app.use(rateLimit());

// ======================
// 📝 API Routes
// ======================

// POST /api/register
app.post('/api/register', rateLimit(), async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ 
      success: false,
      error: 'All fields (username, email, password) are required.' 
    });
  }

  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({ 
      success: false,
      error: 'Username must be 3–20 characters: letters, numbers, underscore.' 
    });
  }

  if (password.length < 8) {
    return res.status(400).json({ 
      success: false,
      error: 'Password must be at least 8 characters long.' 
    });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ 
      success: false,
      error: 'Please enter a valid email address.' 
    });
  }

  try {
    const [users, emails, history] = await Promise.all([
      DataStore.read('users.json'),
      DataStore.read('emails.json'),
      DataStore.read('username_history.json')
    ]);

    // Check if username is currently taken
    if (users[username]) {
      return res.status(400).json({ 
        success: false,
        error: 'Username is currently in use.' 
      });
    }

    // Check if username is in cooldown
    if (history[username]) {
      const releaseTime = new Date(history[username]).getTime() + (USERNAME_LOCK_DAYS * 24 * 60 * 60 * 1000);
      if (Date.now() < releaseTime) {
        const daysLeft = Math.ceil((releaseTime - Date.now()) / (1000 * 60 * 60 * 24));
        return res.status(400).json({ 
          success: false,
          error: `Username is locked for ${daysLeft} more day(s).` 
        });
      }
    }

    // Prevent email reuse
    if (emails[email]) {
      return res.status(400).json({ 
        success: false,
        error: 'This email is already associated with an account.' 
      });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    users[username] = { email, password: hashedPassword };
    emails[email] = username;

    await Promise.all([
      DataStore.write('users.json', users),
      DataStore.write('emails.json', emails)
    ]);

    // Create default profile
    const profiles = await DataStore.read('profiles.json');
    profiles[username] = {
      name: username,
      avatar: 'https://i.imgur.com/uYr99AV.png',
      banner: 'https://i.imgur.com/3M6J3ZP.png',
      bio: '',
      links: [],
      theme: 'dark',
      customCSS: '',
      template: 'default',
      createdAt: new Date().toISOString()
    };
    await DataStore.write('profiles.json', profiles);

    // Generate secure JWT
    const token = jwt.sign(
      { username },
      JWT_SECRET,
      { 
        expiresIn: '24h',
        issuer: 'HostNet-Bio-API',
        audience: username
      }
    );

    res.json({
      success: true,
      token,
      username,
      message: 'Account created successfully.'
    });

  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ 
      success: false,
      error: 'An internal server error occurred. Please try again later.' 
    });
  }
});

// POST /api/login
app.post('/api/login', rateLimit(), async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ 
      success: false,
      error: 'Email and password are required.' 
    });
  }

  try {
    const users = await DataStore.read('users.json');
    const username = Object.keys(users).find(u => users[u].email === email);

    if (!username) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid login credentials.' 
      });
    }

    const match = await bcrypt.compare(password, users[username].password);
    if (!match) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid login credentials.' 
      });
    }

    const token = jwt.sign(
      { username },
      JWT_SECRET,
      { 
        expiresIn: '24h',
        issuer: 'HostNet-Bio-API',
        audience: username
      }
    );

    res.json({
      success: true,
      token,
      username,
      message: 'Login successful.'
    });

  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ 
      success: false,
      error: 'An internal server error occurred. Please try again later.' 
    });
  }
});

// GET /api/user/:id
app.get('/api/user/:id', async (req, res) => {
  try {
    const profiles = await DataStore.read('profiles.json');
    const profile = profiles[req.params.id];

    if (!profile) {
      return res.status(404).json({ 
        success: false,
        error: 'User profile not found.' 
      });
    }

    // Return public profile (exclude sensitive data)
    const { password, ...publicProfile } = users[req.params.id] || {};
    res.json({
      success: true,
      data: {
        ...profile,
        username: req.params.id
      }
    });

  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({ 
      success: false,
      error: 'An internal server error occurred.' 
    });
  }
});

// POST /api/user/:id (Save Profile)
app.post('/api/user/:id', authenticateToken, async (req, res) => {
  const userId = req.params.id;

  if (req.user.username !== userId) {
    return res.status(403).json({ 
      success: false,
      error: 'Access denied. You cannot edit this profile.' 
    });
  }

  const {
    name,
    avatar,
    banner,
    bio,
    links,
    theme,
    customCSS,
    template,
    newUsername
  } = req.body;

  try {
    const [users, emails, profiles, history] = await Promise.all([
      DataStore.read('users.json'),
      DataStore.read('emails.json'),
      DataStore.read('profiles.json'),
      DataStore.read('username_history.json')
    ]);

    // Handle username change
    let finalUsername = userId;
    let newToken = null;

    if (newUsername && newUsername !== userId) {
      if (users[newUsername]) {
        return res.status(400).json({ 
          success: false,
          error: 'The requested username is already in use.' 
        });
      }

      if (history[newUsername]) {
        const releaseTime = new Date(history[newUsername]).getTime() + (USERNAME_LOCK_DAYS * 24 * 60 * 60 * 1000);
        if (Date.now() < releaseTime) {
          const daysLeft = Math.ceil((releaseTime - Date.now()) / (1000 * 60 * 60 * 24));
          return res.status(400).json({ 
            success: false,
            error: `Username is locked for ${daysLeft} more day(s).` 
          });
        }
      }

      // Release old username
      const userData = users[userId];
      delete users[userId];
      users[newUsername] = userData;

      emails[userData.email] = newUsername;

      // Move profile
      profiles[newUsername] = profiles[userId];
      delete profiles[userId];

      // Log old username
      history[userId] = new Date().toISOString();

      await Promise.all([
        DataStore.write('users.json', users),
        DataStore.write('emails.json', emails),
        DataStore.write('profiles.json', profiles),
        DataStore.write('username_history.json', history)
      ]);

      finalUsername = newUsername;
      newToken = jwt.sign(
        { username: newUsername },
        JWT_SECRET,
        { expiresIn: '24h', issuer: 'HostNet-Bio-API', audience: newUsername }
      );
    }

    // Update profile
    profiles[finalUsername] = {
      ...profiles[finalUsername],
      name: name || finalUsername,
      avatar: avatar || 'https://i.imgur.com/uYr99AV.png',
      banner: banner || 'https://i.imgur.com/3M6J3ZP.png',
      bio: bio || '',
      links: Array.isArray(links) ? links : [],
      theme: ['dark', 'light'].includes(theme) ? theme : 'dark',
      customCSS: typeof customCSS === 'string' ? customCSS : '',
      template: template || 'default'
    };

    await DataStore.write('profiles.json', profiles);

    res.json({
      success: true,
      token: newToken,
      username: finalUsername,
      message: 'Profile updated successfully.'
    });

  } catch (err) {
    console.error('Save profile error:', err);
    res.status(500).json({ 
      success: false,
      error: 'Failed to save profile. Please try again later.' 
    });
  }
});

// GET /redirect/:user/:url
app.get('/redirect/:user/:url', async (req, res) => {
  const { user, url } = req.params;
  const decodedUrl = decodeURIComponent(url);

  try {
    const clicks = await DataStore.read('clicks.json');
    clicks[user] = clicks[user] || {};
    clicks[user][decodedUrl] = (clicks[user][decodedUrl] || 0) + 1;
    await DataStore.write('clicks.json', clicks);
  } catch (err) {
    console.error('Click tracking failed:', err);
  } finally {
    res.redirect(decodedUrl);
  }
});

// ======================
// 🚀 Start Server
// ======================
async function startServer() {
  await initializeDataDir();
  console.log('📁 Data directory initialized');

  http.listen(PORT, () => {
    console.log(`✅ HostNet Bio API is live on port ${PORT}`);
    console.log(`🌐 Access your service at:`);
    console.log(`   - https://hostnetapi.onrender.com`);
    console.log(`🔒 Endpoints:`);
    console.log(`   POST /api/register`);
    console.log(`   POST /api/login`);
    console.log(`   GET  /api/user/:id`);
    console.log(`   POST /api/user/:id (auth required)`);
    console.log(`   GET  /redirect/:user/:url`);
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});

// ======================
// 🛑 Graceful Shutdown
// ======================
process.on('SIGTERM', () => {
  console.log('\n🛑 Shutting down gracefully...');
  http.close(() => {
    console.log('⏹️ HTTP server closed.');
    process.exit(0);
  });
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
  process.exit(1);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});
