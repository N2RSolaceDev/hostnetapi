// server.js - HostNet Bio API (Secure & Clean)
const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const http = require('http').createServer(app);

// ======================
// 🔐 Configuration
// ======================
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const JWT_SECRET = process.env.JWT_SECRET; // ⚠️ Change in prod

// Initialize data directory
async function initializeDataDir() {
  try {
    await fs.access(DATA_DIR);
  } catch {
    await fs.mkdir(DATA_DIR, { recursive: true });
  }

  const files = {
    'users.json': '{}',        // username → { email, password_hash }
    'profiles.json': '{}',     // username → { name, avatar, links }
    'tokens.json': '{}'        // username → edit token (for legacy)
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
// 🛠️ Utility Functions
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
  'http://localhost:5173' // For local development
];

app.use((req, res, next) => {
  const origin = req.headers.origin;

  // Only allow allowed origins
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else if (!origin) {
    // Allow non-browser clients (curl, etc.)
    res.setHeader('Access-Control-Allow-Origin', '*');
  } else {
    // Block all others
    return res.status(403).json({ error: 'CORS not allowed' });
  }

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }

  next();
});

app.use(express.json());

// ======================
// 📝 API Routes
// ======================

// 🟢 Register: POST /api/register
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'All fields required' });
  }

  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({ error: 'Invalid username' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  if (!filterValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email' });
  }

  try {
    const users = await readJSON('users.json');

    if (users[username]) {
      return res.status(400).json({ error: 'Username already taken' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users[username] = { email, password: hashedPassword };
    await writeJSON('users.json', users);

    // Create empty profile
    const profiles = await readJSON('profiles.json');
    profiles[username] = {
      name: username.charAt(0).toUpperCase() + username.slice(1),
      avatar: 'https://i.imgur.com/uYr99AV.png',
      links: []
    };
    await writeJSON('profiles.json', profiles);

    // Generate JWT
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });

    res.json({ token, username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 🟡 Login: POST /api/login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  try {
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
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// 🟦 Get Profile: GET /api/user/:id
app.get('/api/user/:id', async (req, res) => {
  try {
    const profiles = await readJSON('profiles.json');
    const profile = profiles[req.params.id];

    if (!profile) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(profile);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// 🟨 Save Profile: POST /api/user/:id
app.post('/api/user/:id', async (req, res) => {
  const { username } = req.body;
  const userId = req.params.id;

  // Auth: Must be same user
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });

    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.username !== userId) {
      return res.status(403).json({ error: 'Forbidden' });
    }
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  try {
    const profiles = await readJSON('profiles.json');
    const data = req.body;

    profiles[userId] = {
      name: data.name?.trim() || userId,
      avatar: data.avatar || 'https://i.imgur.com/uYr99AV.png',
      links: Array.isArray(data.links)
        ? data.links
            .filter(link => link.title && link.url)
            .map(link => ({
              title: link.title.substring(0, 50),
              url: link.url,
              icon: link.icon?.substring(0, 10) || '🔗'
            }))
        : []
    };

    await writeJSON('profiles.json', profiles);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Save failed' });
  }
});

// 🟧 Track Click: GET /redirect/:user/:url
app.get('/redirect/:user/:url', async (req, res) => {
  const { user, url } = req.params;
  const decodedUrl = decodeURIComponent(url);

  try {
    const clicks = await readJSON('clicks.json').catch(() => ({}));
    clicks[user] = clicks[user] || {};
    clicks[user][decodedUrl] = (clicks[user][decodedUrl] || 0) + 1;
    await writeJSON('clicks.json', clicks);
  } catch (err) {
    console.error('Tracking error:', err);
  } finally {
    res.redirect(decodedUrl);
  }
});

// ======================
// 🛠️ Helper
// ======================
function filterValidEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

// ======================
// 🚀 Start Server
// ======================
async function startServer() {
  await initializeDataDir();
  console.log('📁 Data directory initialized');

  http.listen(PORT, () => {
    console.log(`✅ HostNet Bio API is live on port ${PORT}`);
    console.log(`🌐 Allowed origins: ${ALLOWED_ORIGINS.join(', ')}`);
    console.log(`🔒 Endpoints:`);
    console.log(`   POST /api/register`);
    console.log(`   POST /api/login`);
    console.log(`   GET  /api/user/:id`);
    console.log(`   POST /api/user/:id`);
    console.log(`   GET  /redirect/:user/:url`);
  });
}

startServer().catch(console.error);

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
