// server.js - HostNet Bio API (Fixed & Secure)
const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const { Server } = require('socket.io');

const app = express();
const http = require('http').createServer(app);
const io = new Server(http);

// ======================
// 🔐 Configuration
// ======================
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');

// Initialize data directory
async function initializeDataDir() {
  try {
    await fs.access(DATA_DIR);
  } catch {
    await fs.mkdir(DATA_DIR, { recursive: true });
  }

  const files = {
    'users.json': '{}',
    'emails.json': '{}',
    'clicks.json': '{}',
    'tokens.json': '{}'
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

// Generate secure token
function generateToken() {
  return require('crypto').randomBytes(16).toString('hex');
}

// ======================
// 🌐 CORS Setup (NO TRAILING SPACES!)
// ======================
const ALLOWED_ORIGINS = [
  'https://hostnet.ct.ws',
  'https://hostnet.wiki',
  'https://yourname.000webhostapp.com', // Replace with your actual subdomain
  'http://localhost:5173'
];

app.use((req, res, next) => {
  const origin = req.headers.origin;

  // Only allow origins in the list
  if (origin && !ALLOWED_ORIGINS.includes(origin)) {
    return res.status(403).json({ error: 'CORS not allowed' });
  }

  // Set allowed origin (or default to *)
  res.setHeader('Access-Control-Allow-Origin', origin || '*');
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
// 📝 API Routes
// ======================

// GET /api/user/:id
app.get('/api/user/:id', async (req, res) => {
  try {
    const users = await readJSON('users.json');
    const user = users[req.params.id];
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/user/:id → Save user + email + return token
app.post('/api/user/:id', async (req, res) => {
  const { username, email, ...profile } = req.body;
  const userId = req.params.id;

  if (!/^[a-zA-Z0-9_]{3,20}$/.test(userId)) {
    return res.status(400).json({ error: 'Invalid username' });
  }

  try {
    // Save user
    const users = await readJSON('users.json');
    users[userId] = {
      name: profile.name || username || userId,
      avatar: profile.avatar || 'https://i.imgur.com/uYr99AV.png',
      links: Array.isArray(profile.links) ? profile.links : []
    };
    await writeJSON('users.json', users);

    // Save email
    const emails = await readJSON('emails.json');
    emails[userId] = { email, joined: new Date().toISOString() };
    await writeJSON('emails.json', emails);

    // Generate token if not exists
    let tokens = await readJSON('tokens.json');
    if (!tokens[userId]) {
      tokens[userId] = generateToken();
      await writeJSON('tokens.json', tokens);
    }

    // Notify clients
    io.emit('update:' + userId);

    // ✅ Return token for secure redirect
    res.json({
      success: true,
      message: 'Profile saved!',
      token: tokens[userId]
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save' });
  }
});

// GET /api/token/:id
app.get('/api/token/:id', async (req, res) => {
  try {
    const tokens = await readJSON('tokens.json');
    const token = tokens[req.params.id];
    if (token) {
      res.json({ token });
    } else {
      res.status(404).json({ error: 'Token not found' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
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
    io.emit('click:' + user, { url: decodedUrl, count: clicks[user][decodedUrl] });
  } catch (err) {
    console.error('Tracking failed:', err);
  } finally {
    res.redirect(decodedUrl);
  }
});

// ======================
// 🔌 WebSocket
// ======================
io.on('connection', (socket) => {
  console.log('🟢 Client connected:', socket.id);
  socket.on('disconnect', () => {
    console.log('🔴 Client disconnected:', socket.id);
  });
});

// ======================
// 🚀 Start Server
// ======================
async function startServer() {
  await initializeDataDir();
  console.log('📁 Data directory initialized');

  http.listen(PORT, () => {
    console.log(`✅ HostNet Bio API is live on port ${PORT}`);
    console.log(`🌐 Allowed origins: ${ALLOWED_ORIGINS.join(', ')}`);
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
