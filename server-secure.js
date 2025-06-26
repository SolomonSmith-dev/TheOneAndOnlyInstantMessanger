require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const Database = require('./database');

const app = express();
const server = http.createServer(app);

// Initialize database
const db = new Database();

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "ws:", "wss:"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
    message: {
        error: 'Too many requests from this IP, please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

app.use(limiter);

// Stricter rate limiting for auth endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: {
        error: 'Too many authentication attempts, please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// CORS configuration
const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = process.env.ALLOWED_ORIGINS ? 
            process.env.ALLOWED_ORIGINS.split(',') : 
            ['http://localhost:3000', 'http://192.168.1.44:3000'];
        
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// Body parsing middleware
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// Static files
app.use(express.static('public'));

// Environment variables with defaults
const JWT_SECRET = process.env.JWT_SECRET || 'aim-clone-secret-key-2024';
const SESSION_DURATION = parseInt(process.env.SESSION_DURATION_HOURS) || 24;
const MAX_LOGIN_ATTEMPTS = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5;
const ACCOUNT_LOCKOUT_DURATION = parseInt(process.env.ACCOUNT_LOCKOUT_DURATION_MINUTES) || 15;
const MIN_PASSWORD_LENGTH = parseInt(process.env.MIN_PASSWORD_LENGTH) || 8;

// Input validation middleware
const validateRegistration = [
    body('username')
        .isLength({ min: 3, max: 20 })
        .withMessage('Username must be between 3 and 20 characters')
        .matches(/^[a-zA-Z0-9_]+$/)
        .withMessage('Username can only contain letters, numbers, and underscores')
        .trim()
        .escape(),
    body('email')
        .isEmail()
        .withMessage('Must be a valid email address')
        .normalizeEmail(),
    body('password')
        .isLength({ min: MIN_PASSWORD_LENGTH })
        .withMessage(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`)
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
        .withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number')
];

const validateLogin = [
    body('username')
        .isLength({ min: 3, max: 20 })
        .withMessage('Username must be between 3 and 20 characters')
        .trim()
        .escape(),
    body('password')
        .isLength({ min: 1 })
        .withMessage('Password is required')
];

const validateBuddy = [
    body('buddyUsername')
        .isLength({ min: 3, max: 20 })
        .withMessage('Buddy username must be between 3 and 20 characters')
        .matches(/^[a-zA-Z0-9_]+$/)
        .withMessage('Buddy username can only contain letters, numbers, and underscores')
        .trim()
        .escape()
];

// Authentication middleware
const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ error: 'Access token required' });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Validate session in database
        const session = await db.validateSession(token);
        if (!session) {
            return res.status(401).json({ error: 'Invalid or expired session' });
        }

        req.user = session;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired' });
        }
        return res.status(403).json({ error: 'Invalid token' });
    }
};

// Security logging middleware
const securityLog = (req, res, next) => {
    const logData = {
        timestamp: new Date().toISOString(),
        method: req.method,
        url: req.url,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId: req.user ? req.user.id : null
    };
    
    if (req.url.includes('/api/login') || req.url.includes('/api/register')) {
        console.log('🔐 Security Event:', logData);
    }
    
    next();
};

app.use(securityLog);

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Register endpoint with validation
app.post('/api/register', authLimiter, validateRegistration, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                error: 'Validation failed', 
                details: errors.array() 
            });
        }

        const { username, password, email } = req.body;
        
        const existingUser = await db.getUserByUsername(username);
        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        const user = await db.createUser(username, email, password);
        
        const token = jwt.sign(
            { username: user.username, userId: user.id },
            JWT_SECRET,
            { expiresIn: `${SESSION_DURATION}h` }
        );

        const expiresAt = new Date(Date.now() + SESSION_DURATION * 60 * 60 * 1000);
        await db.saveSession(user.id, token, expiresAt.toISOString());

        await db.recordLoginAttempt(username, req.ip, true, req.get('User-Agent'));
        
        res.json({ 
            token, 
            username: user.username, 
            userId: user.id,
            message: 'Registration successful'
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Login endpoint with validation and security
app.post('/api/login', authLimiter, validateLogin, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                error: 'Validation failed', 
                details: errors.array() 
            });
        }

        const { username, password } = req.body;
        
        const user = await db.getUserByUsername(username);
        if (!user) {
            await db.recordLoginAttempt(username, req.ip, false, req.get('User-Agent'));
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        const isLocked = await db.isAccountLocked(user.id);
        if (isLocked) {
            return res.status(423).json({ error: 'Account is temporarily locked due to too many failed attempts' });
        }

        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            await db.incrementFailedAttempts(user.id);
            await db.recordLoginAttempt(username, req.ip, false, req.get('User-Agent'));
            
            const failedAttempts = await db.getFailedLoginAttempts(username, req.ip, 15);
            if (failedAttempts >= MAX_LOGIN_ATTEMPTS) {
                await db.lockAccount(user.id, ACCOUNT_LOCKOUT_DURATION);
                return res.status(423).json({ 
                    error: `Account locked for ${ACCOUNT_LOCKOUT_DURATION} minutes due to too many failed attempts` 
                });
            }
            
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        await db.resetFailedAttempts(user.id);
        await db.updateLastLogin(user.id);
        await db.recordLoginAttempt(username, req.ip, true, req.get('User-Agent'));

        const token = jwt.sign(
            { username: user.username, userId: user.id },
            JWT_SECRET,
            { expiresIn: `${SESSION_DURATION}h` }
        );

        const expiresAt = new Date(Date.now() + SESSION_DURATION * 60 * 60 * 1000);
        await db.saveSession(user.id, token, expiresAt.toISOString());
        
        res.json({ 
            token, 
            username: user.username, 
            userId: user.id,
            message: 'Login successful'
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Logout endpoint
app.post('/api/logout', authenticateToken, async (req, res) => {
    try {
        await db.clearSession(req.user.id);
        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get buddies endpoint
app.get('/api/buddies', authenticateToken, async (req, res) => {
    try {
        const buddies = await db.getBuddies(req.user.id);
        res.json(buddies);
    } catch (error) {
        console.error('Get buddies error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Add buddy endpoint with validation
app.post('/api/buddies', authenticateToken, validateBuddy, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                error: 'Validation failed', 
                details: errors.array() 
            });
        }

        const { buddyUsername } = req.body;
        
        const buddyUser = await db.getUserByUsername(buddyUsername);
        if (!buddyUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        const buddies = await db.getBuddies(req.user.id);
        if (buddies.some(b => b.username === buddyUsername)) {
            return res.status(400).json({ error: 'Already buddies with this user' });
        }

        await db.addBuddy(req.user.id, buddyUsername);
        res.json({ message: 'Buddy added successfully' });
    } catch (error) {
        console.error('Add buddy error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Remove buddy endpoint
app.delete('/api/buddies/:username', authenticateToken, async (req, res) => {
    try {
        const { username } = req.params;
        await db.removeBuddy(req.user.id, username);
        res.json({ message: 'Buddy removed successfully' });
    } catch (error) {
        console.error('Remove buddy error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get message history
app.get('/api/messages/:userId', authenticateToken, async (req, res) => {
    try {
        const { userId } = req.params;
        const limit = parseInt(req.query.limit) || 50;
        
        if (limit > 100) {
            return res.status(400).json({ error: 'Limit cannot exceed 100 messages' });
        }

        const messages = await db.getMessageHistory(req.user.id, parseInt(userId), limit);
        res.json(messages);
    } catch (error) {
        console.error('Get messages error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update away message
app.put('/api/away-message', authenticateToken, [
    body('awayMessage')
        .isLength({ max: 200 })
        .withMessage('Away message must be less than 200 characters')
        .trim()
        .escape()
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                error: 'Validation failed', 
                details: errors.array() 
            });
        }

        const { awayMessage } = req.body;
        await db.updateAwayMessage(req.user.id, awayMessage);
        res.json({ message: 'Away message updated successfully' });
    } catch (error) {
        console.error('Update away message error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Socket.IO with security
const io = socketIo(server, {
    cors: {
        origin: process.env.ALLOWED_ORIGINS ? 
            process.env.ALLOWED_ORIGINS.split(',') : 
            ['http://localhost:3000', 'http://192.168.1.44:3000'],
        methods: ["GET", "POST"],
        credentials: true
    },
    allowEIO3: false,
    transports: ['websocket', 'polling']
});

// Socket authentication middleware
io.use(async (socket, next) => {
    try {
        const token = socket.handshake.auth.token;
        if (!token) {
            return next(new Error('Authentication error'));
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const session = await db.validateSession(token);
        
        if (!session) {
            return next(new Error('Invalid session'));
        }

        socket.user = session;
        next();
    } catch (error) {
        next(new Error('Authentication error'));
    }
});

// Socket.IO connection handling
io.on('connection', async (socket) => {
    console.log('User connected:', socket.id, 'User:', socket.user.username);

    try {
        await db.updateUserStatus(socket.user.id, 'online');
        socket.username = socket.user.username;
        
        const buddies = await db.getBuddies(socket.user.id);
        socket.emit('buddyList', buddies);
        
        for (const buddy of buddies) {
            const buddyUser = await db.getUserByUsername(buddy.username);
            if (buddyUser) {
                socket.to(buddyUser.id).emit('buddyStatusChange', {
                    username: socket.username,
                    status: 'online'
                });
            }
        }

        socket.on('sendMessage', async (data) => {
            try {
                const { to, message } = data;
                
                if (!message || message.length > 1000) {
                    socket.emit('error', { message: 'Invalid message' });
                    return;
                }

                const targetUser = await db.getUserByUsername(to);
                if (!targetUser) {
                    socket.emit('error', { message: 'User not found' });
                    return;
                }

                await db.saveMessage(socket.user.id, targetUser.id, message);

                socket.to(targetUser.id).emit('newMessage', {
                    from: socket.username,
                    message: message,
                    timestamp: new Date().toISOString()
                });

                socket.emit('messageSent', {
                    to,
                    message,
                    timestamp: new Date().toISOString()
                });
            } catch (error) {
                console.error('Send message error:', error);
                socket.emit('error', { message: 'Failed to send message' });
            }
        });

        socket.on('setAwayMessage', async (data) => {
            try {
                const { awayMessage } = data;
                if (awayMessage && awayMessage.length <= 200) {
                    await db.updateAwayMessage(socket.user.id, awayMessage);
                }
            } catch (error) {
                console.error('Set away message error:', error);
            }
        });

        socket.on('statusChange', async (data) => {
            try {
                const { status } = data;
                if (['online', 'away', 'busy', 'offline'].includes(status)) {
                    await db.updateUserStatus(socket.user.id, status);
                    
                    const buddies = await db.getBuddies(socket.user.id);
                    for (const buddy of buddies) {
                        const buddyUser = await db.getUserByUsername(buddy.username);
                        if (buddyUser) {
                            socket.to(buddyUser.id).emit('buddyStatusChange', {
                                username: socket.username,
                                status: status
                            });
                        }
                    }
                }
            } catch (error) {
                console.error('Status change error:', error);
            }
        });

        socket.on('disconnect', async () => {
            console.log('User disconnected:', socket.id, 'User:', socket.username);
            
            if (socket.username) {
                try {
                    await db.updateUserStatus(socket.user.id, 'offline');
                    
                    const buddies = await db.getBuddies(socket.user.id);
                    for (const buddy of buddies) {
                        const buddyUser = await db.getUserByUsername(buddy.username);
                        if (buddyUser) {
                            socket.to(buddyUser.id).emit('buddyStatusChange', {
                                username: socket.username,
                                status: 'offline'
                            });
                        }
                    }
                } catch (error) {
                    console.error('Disconnect error:', error);
                }
            }
        });

    } catch (error) {
        console.error('Socket connection error:', error);
        socket.disconnect();
    }
});

// Cleanup old data periodically
setTimeout(async () => {
    try {
        await db.cleanupOldData();
        console.log('🧹 Cleaned up old data');
    } catch (error) {
        console.error('Cleanup error:', error);
    }
}, 60000); // Run first cleanup after 1 minute

// Run cleanup every 24 hours (86400000 milliseconds)
const CLEANUP_INTERVAL = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
setInterval(async () => {
    try {
        await db.cleanupOldData();
        console.log('🧹 Cleaned up old data');
    } catch (error) {
        console.error('Cleanup error:', error);
    }
}, CLEANUP_INTERVAL);

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('🛑 Shutting down gracefully...');
    await db.close();
    server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
    });
});

process.on('SIGINT', async () => {
    console.log('🛑 Shutting down gracefully...');
    await db.close();
    server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`🔒 Secure AIM Clone server running on port ${PORT}`);
    console.log(`🌐 Local access: http://localhost:${PORT}`);
    console.log(`📱 Mobile access: http://192.168.1.44:${PORT}`);
    console.log(`🔐 Security features: Helmet, Rate Limiting, Input Validation, CORS, JWT Auth`);
}); 