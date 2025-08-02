// server.js - HostNet Bio API
// Runs on Render.com | Connects to PHP frontend
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

// Ensure data directory exists
async function initializeDataDir() {
  try {
    await fs.access(DATA_DIR);
  } catch {
    await fs.mkdir(DATA_DIR, { recursive: true });
  }

  // Initialize data files if not exist
  const files = {
    'users.json': '{}',
    'emails.json': '{}',
    'clicks.json': '{}'
  };

  for (const [filename, defaultContent] of Object.entries(files)) {
    const filePath = path.join(DATA_DIR, filename);
    try {
      await fs.access(filePath);
    } catch {
      await fs.writeFile(filePath, defaultContent, 'utf8');
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
// 🌐 CORS Setup
// ======================
const ALLOWED_ORIGINS = [
  'https://hostnet.ct.ws',
  'https://hostnet.wiki',
  'https://yourname.000webhostapp.com', // Replace with your InfinityFree subdomain
  'http://localhost:5173' // For local dev
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!origin || ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
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
// 📂 Static Assets (Optional)
// ======================
app.use(express.static('public')); // e.g., favicon, logo

// ======================
// 📝 API Routes
// ======================

// GET /api/user/:id → Get user profile
app.get('/api/user/:id', async (req, res) => {
  try {
    const users = await readJSON('users.json');
    const user = users[req.params.id];

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/user/:id → Save user + email
app.post('/api/user/:id', async (req, res) => {
  const { username, email, ...profile } = req.body;

  // Validate username
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(req.params.id)) {
    return res.status(400).json({ error: 'Invalid username' });
  }

  try {
    // Save user profile
    const users = await readJSON('users.json');
    users[req.params.id] = {
      name: profile.name || username || req.params.id,
      avatar: profile.avatar || 'https://i.imgur.com/uYr99AV.png',
      links: Array.isArray(profile.links) ? profile.links : []
    };
    await writeJSON('users.json', users);

    // Save email
    const emails = await readJSON('emails.json');
    emails[req.params.id] = {
      email: email,
      joined: new Date().toISOString()
    };
    await writeJSON('emails.json', emails);

    // Notify real-time clients
    io.emit('update:' + req.params.id);

    res.json({ success: true, message: 'Profile saved!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save' });
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

    // Emit real-time event
    io.emit('click:' + user, { url: decodedUrl, count: clicks[user][decodedUrl] });

    // Redirect
    res.redirect(decodedUrl);
  } catch (err) {
    res.redirect(decodedUrl); // Redirect anyway
  }
});

// GET /api/stats/:user → Get click stats (admin use)
app.get('/api/stats/:user', async (req, res) => {
  try {
    const clicks = await readJSON('clicks.json');
    res.json(clicks[req.params.user] || {});
  } catch (err) {
    res.status(500).json({ error: 'Could not load stats' });
  }
});

// GET /api/users → List all usernames (optional)
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
    console.log(`Socket ${socket.id} joined room: ${room}`);
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
    console.log(`   - GET  /api/user/:id`);
    console.log(`   - POST /api/user/:id`);
    console.log(`   - GET  /redirect/:user/:url`);
    console.log(`   - GET  /api/stats/:user`);
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
