const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// In-memory storage (in a real app, you'd use a database)
const users = new Map();
const onlineUsers = new Map();
const JWT_SECRET = 'aim-clone-secret-key-2024';

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Register endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, email } = req.body;
    
    if (users.has(username)) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();
    
    users.set(username, {
      id: userId,
      username,
      password: hashedPassword,
      email,
      buddies: [],
      awayMessage: 'I am currently away from my computer.',
      status: 'offline'
    });

    const token = jwt.sign({ username, userId }, JWT_SECRET, { expiresIn: '24h' });
    
    res.json({ token, username, userId });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = users.get(username);
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ username, userId: user.id }, JWT_SECRET, { expiresIn: '24h' });
    
    res.json({ token, username, userId: user.id });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get buddies endpoint
app.get('/api/buddies', authenticateToken, (req, res) => {
  const user = users.get(req.user.username);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  const buddyList = user.buddies.map(buddy => {
    const buddyUser = users.get(buddy);
    return {
      username: buddy,
      status: onlineUsers.has(buddy) ? 'online' : 'offline',
      awayMessage: buddyUser ? buddyUser.awayMessage : ''
    };
  });
  
  res.json(buddyList);
});

// Add buddy endpoint
app.post('/api/buddies', authenticateToken, (req, res) => {
  const { buddyUsername } = req.body;
  const user = users.get(req.user.username);
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  if (!users.has(buddyUsername)) {
    return res.status(404).json({ error: 'Buddy not found' });
  }
  
  if (!user.buddies.includes(buddyUsername)) {
    user.buddies.push(buddyUsername);
  }
  
  res.json({ message: 'Buddy added successfully' });
});

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('login', (data) => {
    const { username } = data;
    onlineUsers.set(username, socket.id);
    socket.username = username;
    
    // Update user status
    const user = users.get(username);
    if (user) {
      user.status = 'online';
    }
    
    // Notify buddies
    if (user && user.buddies) {
      user.buddies.forEach(buddy => {
        const buddySocketId = onlineUsers.get(buddy);
        if (buddySocketId) {
          io.to(buddySocketId).emit('buddyStatusChange', {
            username,
            status: 'online'
          });
        }
      });
    }
    
    // Send buddy list to user
    const buddyList = user ? user.buddies.map(buddy => ({
      username: buddy,
      status: onlineUsers.has(buddy) ? 'online' : 'offline'
    })) : [];
    
    socket.emit('buddyList', buddyList);
  });

  socket.on('sendMessage', (data) => {
    const { to, message } = data;
    const from = socket.username;
    
    const targetSocketId = onlineUsers.get(to);
    if (targetSocketId) {
      io.to(targetSocketId).emit('newMessage', {
        from,
        message,
        timestamp: new Date().toISOString()
      });
    }
    
    // Send confirmation back to sender
    socket.emit('messageSent', {
      to,
      message,
      timestamp: new Date().toISOString()
    });
  });

  socket.on('setAwayMessage', (data) => {
    const { awayMessage } = data;
    const username = socket.username;
    
    const user = users.get(username);
    if (user) {
      user.awayMessage = awayMessage;
    }
  });

  socket.on('disconnect', () => {
    const username = socket.username;
    if (username) {
      onlineUsers.delete(username);
      
      // Update user status
      const user = users.get(username);
      if (user) {
        user.status = 'offline';
      }
      
      // Notify buddies
      if (user && user.buddies) {
        user.buddies.forEach(buddy => {
          const buddySocketId = onlineUsers.get(buddy);
          if (buddySocketId) {
            io.to(buddySocketId).emit('buddyStatusChange', {
              username,
              status: 'offline'
            });
          }
        });
      }
    }
    
    console.log('User disconnected:', socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`AIM Clone server running on port ${PORT}`);
  console.log(`Visit http://localhost:${PORT} to start chatting!`);
}); 