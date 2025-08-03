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
    'tokens.json': '{}'  // ← Added: Token storage
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
// 🌐 CORS Setup (NO EXTRA SPACES!)
// ======================
const ALLOWED_ORIGINS = [
  'https://hostnet.ct.ws',
  'https://hostnet.wiki',
  'https://yourname.000webhostapp.com', // Replace with your actual subdomain
  'http://localhost:5173'
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!origin || ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
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
// 📂 Serve Static Files (Important!)
// ======================
// This allows /u.php, /index.php, etc. to be accessed via proxy or CDN
app.use(express.static('public')); // Optional: for favicon, etc.

// ======================
// 📝 API Routes
// ======================

// GET /api/user/:id → Get user profile
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

// POST /api/user/:id → Save user + email + generate token
app.post('/api/user/:id', async (req, res) => {
  const { username, email, ...profile } = req.body;
  const userId = req.params.id;

  // Validate username
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

    // Generate and save edit token if not exists
    let tokens = await readJSON('tokens.json');
    if (!tokens[userId]) {
      tokens[userId] = generateToken();
      await writeJSON('tokens.json', tokens);
    }

    // Notify real-time clients
    io.emit('update:' + userId);

    // ✅ Return token so frontend can redirect securely
    res.json({
      success: true,
      message: 'Profile saved!',
      token: tokens[userId]  // ← Critical: Return token
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save' });
  }
});

// GET /api/token/:id → Get edit token
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

// GET /redirect/:user/:url → Track click & redirect
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

// GET /api/stats/:user → Click stats
app.get('/api/stats/:user', async (req, res) => {
  try {
    const clicks = await readJSON('clicks.json');
    res.json(clicks[req.params.user] || {});
  } catch (err) {
    res.status(500).json({ error: 'Could not load stats' });
  }
});

// GET /api/users → List all usernames
app.get('/api/users', async (req, res) => {
  try {
    const users = await readJSON('users.json');
    res.json(Object.keys(users));
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ======================
// 🔌 WebSocket Real-Time Updates
// ======================
io.on('connection', (socket) => {
  console.log('🟢 Client connected:', socket.id);

  socket.on('disconnect', () => {
    console.log('🔴 Client disconnected:', socket.id);
  });

  socket.on('join', (room) => {
    socket.join(room);
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
    console.log(`🌐 Access your service at:`);
    console.log(`   - https://hostnet.ct.ws`);
    console.log(`   - https://hostnetapi.onrender.com`);
    console.log(`🔒 API Endpoints:`);
    console.log(`   - POST /api/user/:id (returns token)`);
    console.log(`   - GET  /api/token/:id`);
    console.log(`   - GET  /redirect/:user/:url`);
  });
}

startServer().catch(console.error);

// ======================
// 🛑 Graceful Shutdown
// ======================
process.on('SIGTERM', () => {
  console.log('🛑 Shutting down gracefully...');
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
