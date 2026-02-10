const sqlite3 = require("sqlite3").verbose();

const db = new sqlite3.Database("./blog.db", (err) => {
  if (err) console.error("DB error:", err.message);
  else console.log("DB connected");
});

// Improve performance and concurrency
db.serialize(() => {
  try {
    db.run("PRAGMA foreign_keys = ON;");
    db.run("PRAGMA journal_mode = WAL;");
    db.run("PRAGMA synchronous = NORMAL;");
  } catch (e) {
    // ignore if PRAGMA unsupported
  }
});

// Create users table
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    avatar TEXT DEFAULT '',
    full_name TEXT DEFAULT '',
    bio TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

// Add is_admin column for existing databases (safe if already present)
db.run(`ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0`, () => {});
// Add is_super_admin column (THE super admin - only ONE person, fully protected)
db.run(`ALTER TABLE users ADD COLUMN is_super_admin INTEGER DEFAULT 0`, () => {});
// Add is_promoted_admin column (promoted admins - can be multiple, limited permissions)
db.run(`ALTER TABLE users ADD COLUMN is_promoted_admin INTEGER DEFAULT 0`, () => {});
// Add avatar column for existing databases (safe if already present)
db.run(`ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT ''`, () => {});

// Migration: Ensure only ONE super admin exists
// Priority: 1) Keep existing super admin if set, 2) Use 'admin' username, 3) First admin by ID
db.serialize(() => {
  // Check if there's already a super admin
  db.get(`SELECT id, username FROM users WHERE is_super_admin = 1 LIMIT 1`, (err, existingSuperAdmin) => {
    if (existingSuperAdmin) {
      // Super admin already exists, just ensure others are promoted admins
      db.run(`UPDATE users SET is_promoted_admin = 1 WHERE is_admin = 1 AND is_super_admin = 0`);
      console.log('[db] Super Admin already set:', existingSuperAdmin.username);
      return;
    }
    
    // No super admin set - prefer username 'admin' if exists
    db.get(`SELECT id FROM users WHERE is_admin = 1 AND username = 'admin'`, (err, adminUser) => {
      if (adminUser) {
        // Make 'admin' the super admin
        db.run(`UPDATE users SET is_super_admin = 1, is_promoted_admin = 0 WHERE id = ?`, [adminUser.id]);
        db.run(`UPDATE users SET is_super_admin = 0, is_promoted_admin = 1 WHERE is_admin = 1 AND id != ?`, [adminUser.id]);
        console.log('[db] Admin hierarchy migration complete. Super Admin: admin (ID:', adminUser.id + ')');
      } else {
        // Fallback to first admin by ID
        db.get(`SELECT id FROM users WHERE is_admin = 1 ORDER BY id ASC LIMIT 1`, (err, firstAdmin) => {
          if (!firstAdmin) return;
          db.run(`UPDATE users SET is_super_admin = 1, is_promoted_admin = 0 WHERE id = ?`, [firstAdmin.id]);
          db.run(`UPDATE users SET is_super_admin = 0, is_promoted_admin = 1 WHERE is_admin = 1 AND id != ?`, [firstAdmin.id]);
          console.log('[db] Admin hierarchy migration complete. Super Admin ID:', firstAdmin.id);
        });
      }
    });
  });
});

// Create posts table with author_id
db.run(`
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    tags TEXT DEFAULT '',
    FOREIGN KEY (author_id) REFERENCES users(id)
  )
`);

// Add author_id column to existing posts (if not present)
db.run(`ALTER TABLE posts ADD COLUMN author_id INTEGER DEFAULT 1`, (err) => {
  // Safe — if column exists, error is silently ignored
  if (!err) {
    db.run(`UPDATE posts SET author_id = 1 WHERE author_id IS NULL`);
  }
});

// Add is_flagged column for admin flagging
db.run(`ALTER TABLE posts ADD COLUMN is_flagged INTEGER DEFAULT 0`, (err) => {
  // Safe — if column exists, error is silently ignored
});

// Create comments table
db.run(`
  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )
`);

// Create reactions table (for useful/not useful thumbs)
// reaction_type: 'useful' or 'notuseful'
// User can have at most one reaction per post
db.run(`
  CREATE TABLE IF NOT EXISTS reactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    reaction_type TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(post_id, user_id)
  )
`);

// Create bookmarks table (user saved posts)
db.run(`
  CREATE TABLE IF NOT EXISTS bookmarks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    post_id INTEGER NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    UNIQUE(user_id, post_id)
  )
`);

// Notifications (user-only, can be tied to posts or system notifications)
db.run(`
  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    post_id INTEGER,
    type TEXT NOT NULL,
    message TEXT NOT NULL,
    is_read INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
  )
`);

// Create useful indexes to speed up common queries
db.run(`CREATE INDEX IF NOT EXISTS idx_posts_author_id ON posts(author_id)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts(created_at DESC)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_posts_is_flagged ON posts(is_flagged)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_posts_title ON posts(title)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_posts_tags ON posts(tags)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_users_is_admin ON users(is_admin)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_comments_user_id ON comments(user_id)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_reactions_post_id ON reactions(post_id)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_reactions_user_id ON reactions(user_id)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_bookmarks_user_id ON bookmarks(user_id)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_bookmarks_post_id ON bookmarks(post_id)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_notifications_user_id_created_at ON notifications(user_id, created_at DESC)`);

module.exports = db;
