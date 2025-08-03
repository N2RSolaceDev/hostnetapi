// server.js - HostNet Bio API (Full Customization)
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
const USERNAME_LOCK_DAYS = 7;

// Initialize data
async function init() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  for (const file of ['users.json', 'profiles.json', 'emails.json', 'username_history.json', 'templates.json']) {
    const p = path.join(DATA_DIR, file);
    try { await fs.access(p); } 
    catch (err) { await fs.writeFile(p, '{}', 'utf8'); }
  }
}
init();

async function read(f) { return JSON.parse(await fs.readFile(path.join(DATA_DIR, f), 'utf8')); }
async function write(f, d) { await fs.writeFile(path.join(DATA_DIR, f), JSON.stringify(d, null, 2), 'utf8'); }

// ======================
// 🌐 CORS
// ======================
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (['https://hostnet.wiki', 'https://www.hostnet.wiki'].includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else if (!origin) {
    res.setHeader('Access-Control-Allow-Origin', '*');
  } else {
    return res.status(403).json({ error: 'CORS not allowed' });
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

app.use(express.json());

// ======================
// 🔐 Auth Middleware
// ======================
function authenticateToken(req, res, next) {
  const auth = req.headers['authorization'];
  const token = auth && auth.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
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
  if (!username || !email || !password) return res.status(400).json({ error: 'All fields required' });

  const users = await read('users.json');
  const emails = await read('emails.json');
  const history = await read('username_history.json');

  if (users[username]) {
    return res.status(400).json({ error: 'Username is currently taken' });
  }

  if (history[username]) {
    const releaseTime = new Date(history[username]).getTime() + (USERNAME_LOCK_DAYS * 24 * 60 * 60 * 1000);
    if (Date.now() < releaseTime) {
      const daysLeft = Math.ceil((releaseTime - Date.now()) / (1000 * 60 * 60 * 24));
      return res.status(400).json({ error: `Username locked for ${daysLeft} more days` });
    }
  }

  if (emails[email]) {
    return res.status(400).json({ error: 'Email already in use' });
  }

  const hashed = await bcrypt.hash(password, 10);
  users[username] = { email, password: hashed };
  emails[email] = username;

  await write('users.json', users);
  await write('emails.json', emails);

  const profiles = await read('profiles.json');
  profiles[username] = { 
    name: username, 
    avatar: 'https://i.imgur.com/uYr99AV.png', 
    banner: 'https://i.imgur.com/3M6J3ZP.png',
    bio: '',
    links: [],
    theme: 'dark',
    css: '',
    template: 'default'
  };
  await write('profiles.json', profiles);

  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, username });
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const users = await read('users.json');
  const username = Object.keys(users).find(u => users[u].email === email);
  if (!username) return res.status(400).json({ error: 'Invalid credentials' });

  const match = await bcrypt.compare(password, users[username].password);
  if (!match) return res.status(400).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, username });
});

// GET /api/user/:id
app.get('/api/user/:id', async (req, res) => {
  const profiles = await read('profiles.json');
  const p = profiles[req.params.id];
  p ? res.json(p) : res.status(404).json({ error: 'Not found' });
});

// POST /api/user/:id (save profile)
app.post('/api/user/:id', authenticateToken, async (req, res) => {
  if (req.user.username !== req.params.id) return res.status(403).json({ error: 'Forbidden' });

  const { name, avatar, banner, bio, links, newUsername, theme, css, template } = req.body;
  const users = await read('users.json');
  const profiles = await read('profiles.json');
  const history = await read('username_history.json');

  // ✅ Allow username change
  if (newUsername && newUsername !== req.params.id) {
    if (users[newUsername]) {
      return res.status(400).json({ error: 'New username is taken' });
    }
    if (history[newUsername]) {
      const releaseTime = new Date(history[newUsername]).getTime() + (USERNAME_LOCK_DAYS * 24 * 60 * 60 * 1000);
      if (Date.now() < releaseTime) {
        const daysLeft = Math.ceil((releaseTime - Date.now()) / (1000 * 60 * 60 * 24));
        return res.status(400).json({ error: `Username locked for ${daysLeft} more days` });
      }
    }

    const userData = users[req.params.id];
    delete users[req.params.id];
    users[newUsername] = userData;

    const emails = await read('emails.json');
    emails[userData.email] = newUsername;

    profiles[newUsername] = profiles[req.params.id];
    delete profiles[req.params.id];

    history[req.params.id] = new Date().toISOString();

    await write('users.json', users);
    await write('emails.json', emails);
    await write('profiles.json', profiles);
    await write('username_history.json', history);

    const token = jwt.sign({ username: newUsername }, JWT_SECRET, { expiresIn: '24h' });
    return res.json({ success: true, token, username: newUsername });
  }

  // Save profile
  profiles[req.params.id] = {
    name: name || req.params.id,
    avatar: avatar || 'https://i.imgur.com/uYr99AV.png',
    banner: banner || 'https://i.imgur.com/3M6J3ZP.png',
    bio: bio || '',
    links: Array.isArray(links) ? links : [],
    theme: theme || 'dark',
    css: css || '',
    template: template || 'default'
  };

  await write('profiles.json', profiles);
  res.json({ success: true });
});

// GET /templates
app.get('/templates', async (req, res) => {
  const templates = await read('templates.json');
  res.json(templates);
});

// GET /redirect/:user/:url
app.get('/redirect/:user/:url', async (req, res) => {
  const { user, url } = req.params;
  const decodedUrl = decodeURIComponent(url);
  try {
    const clicks = await read('clicks.json');
    clicks[user] = clicks[user] || {};
    clicks[user][decodedUrl] = (clicks[user][decodedUrl] || 0) + 1;
    await write('clicks.json', clicks);
  } catch (err) {}
  res.redirect(decodedUrl);
});

// ======================
// 🚀 Start
// ======================
http.listen(PORT, () => {
  console.log(`✅ HostNet Bio API running on port ${PORT}`);
});
