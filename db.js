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
    full_name TEXT DEFAULT '',
    bio TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

// Add is_admin column for existing databases (safe if already present)
db.run(`ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0`, () => {});

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

// Create useful indexes to speed up common queries
db.run(`CREATE INDEX IF NOT EXISTS idx_posts_author_id ON posts(author_id)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts(created_at DESC)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_posts_is_flagged ON posts(is_flagged)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_posts_title ON posts(title)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_posts_tags ON posts(tags)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_users_is_admin ON users(is_admin)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_comments_user_id ON comments(user_id)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_reactions_post_id ON reactions(post_id)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_reactions_user_id ON reactions(user_id)`);

module.exports = db;
