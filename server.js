// server.js - HostNet Bio API (Final Version)
const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const http = require('http').createServer(app);

// ======================
// 🔐 Config
// ======================
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';

// Initialize data directory
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
    'clicks.json': '{}'
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
// 🛠️ Utils
// ======================
async function readJSON(filename) {
  const content = await fs.readFile(path.join(DATA_DIR, filename), 'utf8');
  return JSON.parse(content);
}

async function writeJSON(filename, data) {
  await fs.writeFile(
    path.join(DATA_DIR, filename),
    JSON.stringify(data, null, 2),
    'utf8'
  );
}

// ======================
// 🌐 CORS Setup (NO UNNECESSARY DOMAINS)
// ======================
const ALLOWED_ORIGINS = [
  'https://hostnet.ct.ws',
  'https://hostnet.wiki',
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
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }

  next();
});

app.use(express.json());

// ======================
// 🔐 Auth Middleware
// ======================
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// ======================
// 📝 API Routes
// ======================

// POST /api/register
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields required' });
  }

  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({ error: 'Invalid username' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password too short' });
  }

  try {
    const users = await readJSON('users.json');
    if (users[username]) {
      return res.status(400).json({ error: 'Username taken' });
    }

    const hashed = await bcrypt.hash(password, 10);
    users[username] = { email, password: hashed };
    await writeJSON('users.json', users);

    // Create profile
    const profiles = await readJSON('profiles.json');
    profiles[username] = {
      name: username,
      avatar: 'https://i.imgur.com/uYr99AV.png',
      links: []
    };
    await writeJSON('profiles.json', profiles);

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, username });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const users = await readJSON('users.json');
  const username = Object.keys(users).find(u => users[u].email === email);

  if (!username) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  const match = await bcrypt.compare(password, users[username].password);
  if (!match) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, username });
});

// GET /api/user/:id
app.get('/api/user/:id', async (req, res) => {
  try {
    const profiles = await readJSON('profiles.json');
    const profile = profiles[req.params.id];
    if (!profile) return res.status(404).json({ error: 'Not found' });
    res.json(profile);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/user/:id (save)
app.post('/api/user/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  if (req.user.username !== id) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const { name, avatar, links } = req.body;
  const profiles = await readJSON('profiles.json');

  profiles[id] = {
    name: name || id,
    avatar: avatar || 'https://i.imgur.com/uYr99AV.png',
    links: Array.isArray(links) ? links : []
  };

  await writeJSON('profiles.json', profiles);
  res.json({ success: true });
});

// GET /redirect/:user/:url
app.get('/redirect/:user/:url', async (req, res) => {
  const { user, url } = req.params;
  const decodedUrl = decodeURIComponent(url);

  try {
    const clicks = await readJSON('clicks.json');
    clicks[user] = clicks[user] || {};
    clicks[user][decodedUrl] = (clicks[user][decodedUrl] || 0) + 1;
    await writeJSON('clicks.json', clicks);
  } catch (err) {
    console.error('Tracking failed:', err);
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
  });
}

startServer().catch(console.error);

// ======================
// 🛑 Graceful Shutdown
// ======================
process.on('SIGTERM', () => {
  console.log('🛑 Shutting down...');
  http.close(() => process.exit(0));
});
