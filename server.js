const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const http = require('http').createServer(app);

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';

async function init() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  for (const file of ['users.json', 'profiles.json', 'clicks.json']) {
    const p = path.join(DATA_DIR, file);
    try { await fs.access(p); } 
    catch (err) { await fs.writeFile(p, '{}', 'utf8'); }
  }
}
init();

async function read(f) { return JSON.parse(await fs.readFile(path.join(DATA_DIR, f), 'utf8')); }
async function write(f, d) { await fs.writeFile(path.join(DATA_DIR, f), JSON.stringify(d, null, 2), 'utf8'); }

const ALLOWED_ORIGINS = ['https://hostnet.ct.ws', 'http://localhost:5173'];
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!origin || ALLOWED_ORIGINS.includes(origin)) res.setHeader('Access-Control-Allow-Origin', origin || '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

app.use(express.json());

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

app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'All fields required' });
  const users = await read('users.json');
  if (users[username]) return res.status(400).json({ error: 'Username taken' });
  const hashed = await bcrypt.hash(password, 10);
  users[username] = { email, password: hashed };
  await write('users.json', users);
  const profiles = await read('profiles.json');
  profiles[username] = { name: username, avatar: 'https://i.imgur.com/uYr99AV.png', links: [] };
  await write('profiles.json', profiles);
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, username });
});

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

app.get('/api/user/:id', async (req, res) => {
  const profiles = await read('profiles.json');
  const p = profiles[req.params.id];
  p ? res.json(p) : res.status(404).json({ error: 'Not found' });
});

app.post('/api/user/:id', authenticateToken, async (req, res) => {
  if (req.user.username !== req.params.id) return res.status(403).json({ error: 'Forbidden' });
  const profiles = await read('profiles.json');
  profiles[req.params.id] = { ...profiles[req.params.id], ...req.body };
  await write('profiles.json', profiles);
  res.json({ success: true });
});

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

http.listen(PORT, () => {
  console.log(`✅ HostNet Bio API running on port ${PORT}`);
});
