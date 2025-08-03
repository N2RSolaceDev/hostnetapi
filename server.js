const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const http = require('http').createServer(app);

// ======================
// Config
// ======================
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';

// Init
async function init() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  for (const file of ['users.json', 'emails.json', 'tokens.json']) {
    const p = path.join(DATA_DIR, file);
    try { await fs.access(p); } 
    catch (err) { await fs.writeFile(p, '{}', 'utf8'); }
  }
}
init();

// Utils
async function read(f) { return JSON.parse(await fs.readFile(path.join(DATA_DIR, f), 'utf8')); }
async function write(f, d) { await fs.writeFile(path.join(DATA_DIR, f), JSON.stringify(d, null, 2), 'utf8'); }

// CORS
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!origin || ['https://hostnet.ct.ws', 'http://localhost:5173'].includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

app.use(express.json());

// ======================
// API Routes
// ======================

// Register
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'All fields required' });

  const users = await read('users.json');
  if (users[username]) return res.status(400).json({ error: 'Username taken' });

  const hashed = await bcrypt.hash(password, 10);
  users[username] = { email, password: hashed };
  await write('users.json', users);

  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, username });
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const users = await read('users.json');
  const username = Object.keys(users).find(u => users[u].email === email);

  if (!username) return res.status(400).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, users[username].password);
  if (!valid) return res.status(400).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, username });
});

// Get user
app.get('/api/user/:id', async (req, res) => {
  const users = await read('users.json');
  const user = users[req.params.id];
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json(user);
});

// Save user
app.post('/api/user/:id', async (req, res) => {
  const { username } = req.body;
  if (req.params.id !== username) return res.status(403).json({ error: 'Forbidden' });

  const users = await read('users.json');
  users[username] = { ...users[username], ...req.body };
  await write('users.json', users);

  res.json({ success: true });
});

// ======================
// Start
// ======================
http.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
