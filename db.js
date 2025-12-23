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
    full_name TEXT DEFAULT '',
    bio TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

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

// Create useful indexes to speed up common queries
db.run(`CREATE INDEX IF NOT EXISTS idx_posts_author_id ON posts(author_id)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts(created_at DESC)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_posts_is_flagged ON posts(is_flagged)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_posts_title ON posts(title)`);
db.run(`CREATE INDEX IF NOT EXISTS idx_posts_tags ON posts(tags)`);

module.exports = db;
