// server.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs').promises;
const path = require('path');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(cors({
  origin: ['https://hostnet.wiki', 'https://www.hostnet.wiki'],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP'
});
app.use(limiter);

// Data directory
const DATA_DIR = './data';
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PROFILES_FILE = path.join(DATA_DIR, 'profiles.json');
const EMAILS_FILE = path.join(DATA_DIR, 'emails.json');
const USERNAME_HISTORY_FILE = path.join(DATA_DIR, 'username_history.json');
const CLICKS_FILE = path.join(DATA_DIR, 'clicks.json');
const RATE_LIMITS_FILE = path.join(DATA_DIR, 'rate_limits.json');

// Ensure data directory exists
async function ensureDataDirectory() {
  try {
    await fs.access(DATA_DIR);
  } catch {
    await fs.mkdir(DATA_DIR, { recursive: true });
  }
}

// Initialize data files with defaults
async function initializeDataFiles() {
  try {
    // Users file
    try {
      await fs.access(USERS_FILE);
    } catch {
      await fs.writeFile(USERS_FILE, '{}');
    }

    // Profiles file
    try {
      await fs.access(PROFILES_FILE);
    } catch {
      await fs.writeFile(PROFILES_FILE, '{}');
    }

    // Emails file
    try {
      await fs.access(EMAILS_FILE);
    } catch {
      await fs.writeFile(EMAILS_FILE, '{}');
    }

    // Username history file
    try {
      await fs.access(USERNAME_HISTORY_FILE);
    } catch {
      await fs.writeFile(USERNAME_HISTORY_FILE, '{}');
    }

    // Clicks file
    try {
      await fs.access(CLICKS_FILE);
    } catch {
      await fs.writeFile(CLICKS_FILE, '{}');
    }

    // Rate limits file
    try {
      await fs.access(RATE_LIMITS_FILE);
    } catch {
      await fs.writeFile(RATE_LIMITS_FILE, '{}');
    }
  } catch (err) {
    console.error('Error initializing data files:', err);
  }
}

// Helper functions
async function readJSONFile(filePath) {
  try {
    const data = await fs.readFile(filePath, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    return {};
  }
}

async function writeJSONFile(filePath, data) {
  try {
    await fs.writeFile(filePath, JSON.stringify(data, null, 2));
    return true;
  } catch (err) {
    console.error(`Error writing to ${filePath}:`, err);
    return false;
  }
}

async function atomicWrite(filePath, data) {
  const tempPath = `${filePath}.tmp`;
  try {
    await fs.writeFile(tempPath, JSON.stringify(data, null, 2));
    await fs.rename(tempPath, filePath);
    return true;
  } catch (err) {
    console.error(`Atomic write failed for ${filePath}:`, err);
    try {
      await fs.unlink(tempPath);
    } catch {}
    return false;
  }
}

function generateJWT(payload) {
  const secret = process.env.JWT_SECRET || 'default_secret_key';
  return jwt.sign(payload, secret, { expiresIn: '24h' });
}

function verifyJWT(token) {
  const secret = process.env.JWT_SECRET || 'default_secret_key';
  try {
    return jwt.verify(token, secret);
  } catch (err) {
    return null;
  }
}

// Validation helpers
function validateUsername(username) {
  if (!username || username.length < 3 || username.length > 20) {
    return 'Username must be between 3 and 20 characters';
  }
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return 'Username can only contain letters, numbers, and underscores';
  }
  return null;
}

function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRegex.test(email)) {
    return 'Invalid email format';
  }
  return null;
}

function validatePassword(password) {
  if (!password || password.length < 6) {
    return 'Password must be at least 6 characters';
  }
  return null;
}

// Routes
// Register endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validate inputs
    const usernameError = validateUsername(username);
    const emailError = validateEmail(email);
    const passwordError = validatePassword(password);

    if (usernameError) return res.status(400).json({ error: usernameError });
    if (emailError) return res.status(400).json({ error: emailError });
    if (passwordError) return res.status(400).json({ error: passwordError });

    // Check if email already exists
    const emails = await readJSONFile(EMAILS_FILE);
    if (emails[email]) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Check username cooldown
    const usernameHistory = await readJSONFile(USERNAME_HISTORY_FILE);
    if (usernameHistory[username]) {
      const lastUsed = new Date(usernameHistory[username]);
      const now = new Date();
      const diffDays = Math.floor((now - lastUsed) / (1000 * 60 * 60 * 24));
      if (diffDays < 7) {
        return res.status(400).json({ error: 'Username is on cooldown' });
      }
    }

    // Check if username already exists
    const users = await readJSONFile(USERS_FILE);
    if (users[username]) {
      return res.status(400).json({ error: 'Username already taken' });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const newUser = {
      email,
      password_hash: hashedPassword,
      createdAt: new Date().toISOString()
    };

    // Update data files
    users[username] = newUser;
    emails[email] = username;
    
    const profiles = await readJSONFile(PROFILES_FILE);
    profiles[username] = {
      name: username,
      avatar: '',
      banner: '',
      bio: '',
      links: [],
      theme: 'light',
      customCSS: ''
    };
    
    const usernameHistoryUpdated = { ...usernameHistory };
    delete usernameHistoryUpdated[username];

    const success = await Promise.all([
      atomicWrite(USERS_FILE, users),
      atomicWrite(EMAILS_FILE, emails),
      atomicWrite(PROFILES_FILE, profiles),
      atomicWrite(USERNAME_HISTORY_FILE, usernameHistoryUpdated)
    ]);

    if (!success.every(Boolean)) {
      return res.status(500).json({ error: 'Registration failed' });
    }

    // Generate JWT
    const token = generateJWT({ username, iss: 'hostnet', aud: 'hostnet-users' });

    res.json({ token, username });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate inputs
    const emailError = validateEmail(email);
    const passwordError = validatePassword(password);

    if (emailError) return res.status(400).json({ error: emailError });
    if (passwordError) return res.status(400).json({ error: passwordError });

    // Find user
    const users = await readJSONFile(USERS_FILE);
    const user = Object.entries(users).find(([_, userData]) => userData.email === email);

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const [username, userData] = user;

    // Verify password
    const isValid = await bcrypt.compare(password, userData.password_hash);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT
    const token = generateJWT({ username, iss: 'hostnet', aud: 'hostnet-users' });

    res.json({ token, username });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user profile
app.get('/api/user/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const profiles = await readJSONFile(PROFILES_FILE);
    const profile = profiles[id];
    
    if (!profile) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Remove sensitive data
    const publicProfile = {
      name: profile.name,
      avatar: profile.avatar,
      banner: profile.banner,
      bio: profile.bio,
      links: profile.links,
      theme: profile.theme
    };
    
    res.json(publicProfile);
  } catch (err) {
    console.error('Get user profile error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update user profile
app.post('/api/user/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const decoded = verifyJWT(token);
    if (!decoded || decoded.username !== id) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const { name, avatar, banner, bio, links, newUsername, theme, customCSS } = req.body;
    
    // Read current data
    const profiles = await readJSONFile(PROFILES_FILE);
    const users = await readJSONFile(USERS_FILE);
    const emails = await readJSONFile(EMAILS_FILE);
    const usernameHistory = await readJSONFile(USERNAME_HISTORY_FILE);
    
    // Validate new username if provided
    let updatedUsername = id;
    if (newUsername && newUsername !== id) {
      const usernameError = validateUsername(newUsername);
      if (usernameError) {
        return res.status(400).json({ error: usernameError });
      }
      
      // Check if username is on cooldown
      if (usernameHistory[newUsername]) {
        const lastUsed = new Date(usernameHistory[newUsername]);
        const now = new Date();
        const diffDays = Math.floor((now - lastUsed) / (1000 * 60 * 60 * 24));
        if (diffDays < 7) {
          return res.status(400).json({ error: 'Username is on cooldown' });
        }
      }
      
      // Check if username already exists
      if (users[newUsername]) {
        return res.status(400).json({ error: 'Username already taken' });
      }
      
      // Update username
      updatedUsername = newUsername;
      
      // Move user data
      users[newUsername] = users[id];
      delete users[id];
      
      // Update email mapping
      emails[users[newUsername].email] = newUsername;
      delete emails[users[id].email];
      
      // Update profile
      profiles[newUsername] = profiles[id];
      delete profiles[id];
      
      // Add old username to history
      usernameHistory[id] = new Date().toISOString();
    }
    
    // Update profile
    const profile = profiles[updatedUsername];
    if (name) profile.name = name;
    if (avatar) profile.avatar = avatar;
    if (banner) profile.banner = banner;
    if (bio) profile.bio = bio;
    if (links) profile.links = links;
    if (theme) profile.theme = theme;
    if (customCSS) profile.customCSS = customCSS;
    
    // Save changes
    const success = await Promise.all([
      atomicWrite(USERS_FILE, users),
      atomicWrite(EMAILS_FILE, emails),
      atomicWrite(PROFILES_FILE, profiles),
      atomicWrite(USERNAME_HISTORY_FILE, usernameHistory)
    ]);
    
    if (!success.every(Boolean)) {
      return res.status(500).json({ error: 'Update failed' });
    }
    
    // Generate new token if username changed
    let newToken = token;
    if (updatedUsername !== id) {
      newToken = generateJWT({ username: updatedUsername, iss: 'hostnet', aud: 'hostnet-users' });
    }
    
    res.json({ token: newToken, username: updatedUsername });
  } catch (err) {
    console.error('Update user profile error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Redirect endpoint
app.get('/redirect/:user/:url', async (req, res) => {
  try {
    const { user, url } = req.params;
    
    // Decode URL
    const decodedUrl = decodeURIComponent(url);
    
    // Increment click count
    try {
      const clicks = await readJSONFile(CLICKS_FILE);
      if (!clicks[user]) clicks[user] = {};
      if (!clicks[user][decodedUrl]) clicks[user][decodedUrl] = 0;
      clicks[user][decodedUrl]++;
      
      await atomicWrite(CLICKS_FILE, clicks);
    } catch (err) {
      console.error('Click tracking failed:', err);
    }
    
    // Redirect
    res.redirect(302, decodedUrl);
  } catch (err) {
    console.error('Redirect error:', err);
    // Fallback redirect to homepage
    res.redirect(302, '/');
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down gracefully...');
  process.exit(0);
});

// Start server
async function startServer() {
  await ensureDataDirectory();
  await initializeDataFiles();
  
  app.listen(PORT, () => {
    console.log(`HostNet API server running on port ${PORT}`);
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
