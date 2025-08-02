const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');

const app = express();
const http = require('http').createServer(app);

// ======================
// 🔐 Configuration
// ======================
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET; // ⚠️ Use env var!

// In-memory storage (replace with MongoDB/Redis later)
const users = [];
const messages = [];

// ======================
// 🌐 CORS for REST API
// ======================
const allowedOrigins = [
  'https://hostnet.ct.ws',
  'https://hostnet.wiki',
  'http://localhost:5173', // For local dev (Vite, etc.)
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS not allowed'));
    }
  },
  methods: ['GET', 'POST'],
  credentials: true
}));

app.use(express.json());

// ======================
// 🔑 JWT Auth Middleware
// ======================
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
    req.user = user;
    next();
  });
}

// ======================
// 📝 REST API Routes
// ======================

// 🟢 Register
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password || username.length < 3 || password.length < 6) {
    return res.status(400).json({ error: 'Username >=3 chars, password >=6 chars.' });
  }

  if (users.find(u => u.username === username)) {
    return res.status(400).json({ error: 'Username already taken.' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });

  console.log(`🆕 Registered: ${username}`);
  res.json({ message: 'User created successfully.' });
});

// 🔐 Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ error: 'Invalid username or password.' });
  }

  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
  console.log(`👤 ${username} logged in`);
  res.json({ token, username });
});

// 📬 Get Messages (for initial load)
app.get('/api/messages', authenticateToken, (req, res) => {
  const channel = req.query.channel || 'general';
  const channelMessages = messages.filter(m => m.channel === channel);
  res.json(channelMessages);
});

// ======================
// 🔌 WebSocket (Socket.IO)
// ======================

const io = new Server(http, {
  cors: {
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Socket origin not allowed.'));
      }
    },
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// Middleware: Authenticate Socket.IO connections
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Authentication required.'));

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return next(new Error('Invalid or expired token.'));
    socket.username = user.username;
    next();
  });
});

// Handle connections
io.on('connection', (socket) => {
  const { username } = socket;
  const channel = socket.handshake.auth.channel || 'general';

  console.log(`🟢 ${username} connected to channel: ${channel}`);

  // Send current messages
  const channelMessages = messages.filter(m => m.channel === channel);
  socket.emit('init', channelMessages);

  // Notify others
  socket.broadcast.emit('user:joined', { username });

  // Listen for new message
  socket.on('send:message', (content) => {
    const message = {
      id: Date.now(),
      username,
      content: content.trim().substring(0, 500),
      channel,
      timestamp: new Date().toISOString()
    };

    messages.push(message);
    if (messages.length > 200) messages.shift(); // Keep last 200 messages

    io.emit('new:message', message); // Broadcast to all
  });

  // Typing indicator (optional)
  socket.on('typing', () => {
    socket.broadcast.emit('user:typing', { username, channel });
  });

  socket.on('disconnect', () => {
    console.log(`🔴 ${username} disconnected`);
    socket.broadcast.emit('user:left', { username });
  });
});

// ======================
// 🚀 Start Server
// ======================
http.listen(PORT, () => {
  console.log(`✅ HostNet API running on port ${PORT}`);
  console.log(`🌐 Access via:`);
  console.log(`   - https://hostnet.ct.ws`);
  console.log(`   - https://hostnet.wiki (soon)`);
  console.log(`   - https://your-project.onrender.com`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Shutting down server...');
  http.close(() => {
    console.log('HTTP server closed.');
  });
});
