const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

class Database {
    constructor() {
        this.db = new sqlite3.Database(path.join(__dirname, 'aim_clone.db'));
        this.init();
    }

    init() {
        return new Promise((resolve, reject) => {
            this.db.serialize(() => {
                // Create users table with proper constraints
                this.db.run(`
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_login DATETIME,
                        status TEXT DEFAULT 'offline',
                        away_message TEXT DEFAULT 'I am currently away from my computer.',
                        failed_login_attempts INTEGER DEFAULT 0,
                        locked_until DATETIME,
                        session_token TEXT,
                        session_expires DATETIME
                    )
                `);

                // Create buddies table for buddy relationships
                this.db.run(`
                    CREATE TABLE IF NOT EXISTS buddies (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        buddy_username TEXT NOT NULL,
                        added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id),
                        UNIQUE(user_id, buddy_username)
                    )
                `);

                // Create messages table for message history
                this.db.run(`
                    CREATE TABLE IF NOT EXISTS messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        sender_id INTEGER NOT NULL,
                        receiver_id INTEGER NOT NULL,
                        message TEXT NOT NULL,
                        sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        read_at DATETIME,
                        FOREIGN KEY (sender_id) REFERENCES users (id),
                        FOREIGN KEY (receiver_id) REFERENCES users (id)
                    )
                `);

                // Create login_attempts table for security monitoring
                this.db.run(`
                    CREATE TABLE IF NOT EXISTS login_attempts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        ip_address TEXT NOT NULL,
                        success BOOLEAN NOT NULL,
                        attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        user_agent TEXT
                    )
                `);

                // Create indexes for better performance
                this.db.run('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)');
                this.db.run('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)');
                this.db.run('CREATE INDEX IF NOT EXISTS idx_buddies_user_id ON buddies(user_id)');
                this.db.run('CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)');
                this.db.run('CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id)');
                this.db.run('CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username)');
                this.db.run('CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address)');

                this.db.run('PRAGMA foreign_keys = ON');
                this.db.run('PRAGMA journal_mode = WAL');
                this.db.run('PRAGMA synchronous = NORMAL');

                resolve();
            });
        });
    }

    // User management methods
    async createUser(username, email, password) {
        return new Promise((resolve, reject) => {
            const saltRounds = 12;
            bcrypt.hash(password, saltRounds, (err, hash) => {
                if (err) {
                    reject(err);
                    return;
                }

                this.db.run(
                    'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                    [username.toLowerCase(), email.toLowerCase(), hash],
                    function(err) {
                        if (err) {
                            reject(err);
                        } else {
                            resolve({ id: this.lastID, username, email });
                        }
                    }
                );
            });
        });
    }

    async getUserByUsername(username) {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT * FROM users WHERE username = ?',
                [username.toLowerCase()],
                (err, row) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(row);
                    }
                }
            );
        });
    }

    async getUserById(id) {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT * FROM users WHERE id = ?',
                [id],
                (err, row) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(row);
                    }
                }
            );
        });
    }

    async updateLastLogin(userId) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
                [userId],
                (err) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve();
                    }
                }
            );
        });
    }

    async updateUserStatus(userId, status) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE users SET status = ? WHERE id = ?',
                [status, userId],
                (err) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve();
                    }
                }
            );
        });
    }

    async updateAwayMessage(userId, awayMessage) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE users SET away_message = ? WHERE id = ?',
                [awayMessage, userId],
                (err) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve();
                    }
                }
            );
        });
    }

    // Buddy management methods
    async addBuddy(userId, buddyUsername) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'INSERT INTO buddies (user_id, buddy_username) VALUES (?, ?)',
                [userId, buddyUsername.toLowerCase()],
                function(err) {
                    if (err) {
                        reject(err);
                    } else {
                        resolve({ id: this.lastID });
                    }
                }
            );
        });
    }

    async getBuddies(userId) {
        return new Promise((resolve, reject) => {
            this.db.all(
                `SELECT b.buddy_username, u.status, u.away_message
                 FROM buddies b
                 LEFT JOIN users u ON b.buddy_username = u.username
                 WHERE b.user_id = ?`,
                [userId],
                (err, rows) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(rows.map(row => ({
                            username: row.buddy_username,
                            status: row.status || 'offline',
                            awayMessage: row.away_message || ''
                        })));
                    }
                }
            );
        });
    }

    async removeBuddy(userId, buddyUsername) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'DELETE FROM buddies WHERE user_id = ? AND buddy_username = ?',
                [userId, buddyUsername.toLowerCase()],
                (err) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve();
                    }
                }
            );
        });
    }

    // Message history methods
    async saveMessage(senderId, receiverId, message) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)',
                [senderId, receiverId, message],
                function(err) {
                    if (err) {
                        reject(err);
                    } else {
                        resolve({ id: this.lastID });
                    }
                }
            );
        });
    }

    async getMessageHistory(userId1, userId2, limit = 50) {
        return new Promise((resolve, reject) => {
            this.db.all(
                `SELECT m.*, u1.username as sender_username, u2.username as receiver_username
                 FROM messages m
                 JOIN users u1 ON m.sender_id = u1.id
                 JOIN users u2 ON m.receiver_id = u2.id
                 WHERE (m.sender_id = ? AND m.receiver_id = ?) 
                    OR (m.sender_id = ? AND m.receiver_id = ?)
                 ORDER BY m.sent_at DESC
                 LIMIT ?`,
                [userId1, userId2, userId2, userId1, limit],
                (err, rows) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(rows.reverse()); // Return in chronological order
                    }
                }
            );
        });
    }

    // Security methods
    async recordLoginAttempt(username, ipAddress, success, userAgent) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'INSERT INTO login_attempts (username, ip_address, success, user_agent) VALUES (?, ?, ?, ?)',
                [username.toLowerCase(), ipAddress, success, userAgent],
                function(err) {
                    if (err) {
                        reject(err);
                    } else {
                        resolve();
                    }
                }
            );
        });
    }

    async getFailedLoginAttempts(username, ipAddress, timeWindow = 15) {
        return new Promise((resolve, reject) => {
            this.db.get(
                `SELECT COUNT(*) as count 
                 FROM login_attempts 
                 WHERE username = ? AND ip_address = ? AND success = 0 
                 AND attempted_at > datetime('now', '-${timeWindow} minutes')`,
                [username.toLowerCase(), ipAddress],
                (err, row) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(row.count);
                    }
                }
            );
        });
    }

    async incrementFailedAttempts(userId) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?',
                [userId],
                (err) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve();
                    }
                }
            );
        });
    }

    async lockAccount(userId, lockDuration = 15) {
        return new Promise((resolve, reject) => {
            this.db.run(
                `UPDATE users 
                 SET locked_until = datetime('now', '+${lockDuration} minutes') 
                 WHERE id = ?`,
                [userId],
                (err) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve();
                    }
                }
            );
        });
    }

    async resetFailedAttempts(userId) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?',
                [userId],
                (err) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve();
                    }
                }
            );
        });
    }

    async isAccountLocked(userId) {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT locked_until FROM users WHERE id = ?',
                [userId],
                (err, row) => {
                    if (err) {
                        reject(err);
                    } else {
                        if (!row || !row.locked_until) {
                            resolve(false);
                        } else {
                            // Check if lock has expired
                            this.db.get(
                                'SELECT 1 FROM users WHERE id = ? AND locked_until > datetime("now")',
                                [userId],
                                (err, lockedRow) => {
                                    if (err) {
                                        reject(err);
                                    } else {
                                        resolve(!!lockedRow);
                                    }
                                }
                            );
                        }
                    }
                }
            );
        });
    }

    // Session management
    async saveSession(userId, token, expiresAt) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE users SET session_token = ?, session_expires = ? WHERE id = ?',
                [token, expiresAt, userId],
                (err) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve();
                    }
                }
            );
        });
    }

    async validateSession(token) {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT id, username FROM users WHERE session_token = ? AND session_expires > datetime("now")',
                [token],
                (err, row) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(row);
                    }
                }
            );
        });
    }

    async clearSession(userId) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'UPDATE users SET session_token = NULL, session_expires = NULL WHERE id = ?',
                [userId],
                (err) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve();
                    }
                }
            );
        });
    }

    // Cleanup methods
    async cleanupOldData() {
        return new Promise((resolve, reject) => {
            // Clean up old login attempts (older than 30 days)
            this.db.run(
                'DELETE FROM login_attempts WHERE attempted_at < datetime("now", "-30 days")',
                (err) => {
                    if (err) {
                        reject(err);
                    } else {
                        // Clean up expired sessions
                        this.db.run(
                            'UPDATE users SET session_token = NULL, session_expires = NULL WHERE session_expires < datetime("now")',
                            (err) => {
                                if (err) {
                                    reject(err);
                                } else {
                                    resolve();
                                }
                            }
                        );
                    }
                }
            );
        });
    }

    close() {
        return new Promise((resolve) => {
            this.db.close((err) => {
                if (err) {
                    console.error('Error closing database:', err);
                }
                resolve();
            });
        });
    }
}

module.exports = Database; 