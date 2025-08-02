const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');

const app = express();
const http = require('http').createServer(app);

// ======================
// Configuration
// ======================
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your-super-secret-jwt-key-change-in-production';

// In-memory storage
const users = [];
const messages = [];

// CORS for REST
app.use(cors({
  origin: [
    'https://your-site.rf.gd',           // ← CHANGE: Your InfinityFree domain
    'https://your-site.000webhostapp.com' // Add others if needed
  ],
  methods: ['GET', 'POST']
}));

app.use(express.json());

// ======================
// JWT Auth Middleware
// ======================
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// ======================
// REST API: Auth
// ======================

// Register
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  if (users.find(u => u.username === username)) {
    return res.status(400).json({ error: 'Username already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });

  res.json({ message: 'User registered successfully' });
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token, username });
});

// Get messages (for initial load)
app.get('/api/messages', authenticateToken, (req, res) => {
  const channel = req.query.channel || 'general';
  const channelMessages = messages.filter(m => m.channel === channel);
  res.json(channelMessages);
});

// ======================
// WebSocket (Socket.IO)
// ======================

const io = new Server(http, {
  cors: {
    origin: [
      'https://your-site.rf.gd',
      'https://your-site.000webhostapp.com'
    ],
    methods: ['GET', 'POST'],
    credentials: true
  }
});

io.use(async (socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Authentication required'));

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return next(new Error('Invalid or expired token'));
    socket.username = user.username;
    next();
  });
});

io.on('connection', (socket) => {
  console.log(`🟢 ${socket.username} connected`);

  // Send existing messages
  const channel = socket.handshake.auth.channel || 'general';
  const channelMessages = messages.filter(m => m.channel === channel);
  socket.emit('init', channelMessages);

  // Notify others
  socket.broadcast.emit('user:joined', { username: socket.username });

  // Listen for new messages
  socket.on('send:message', (content) => {
    const message = {
      username: socket.username,
      content: content.trim(),
      channel,
      timestamp: new Date().toISOString()
    };

    messages.push(message);
    if (messages.length > 100) messages.shift(); // Keep last 100

    io.emit('new:message', message); // Broadcast to all
  });

  socket.on('disconnect', () => {
    console.log(`🔴 ${socket.username} disconnected`);
    io.emit('user:left', { username: socket.username });
  });
});

// ======================
// Start Server
// ======================
http.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
