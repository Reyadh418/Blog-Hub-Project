const sqlite3 = require("sqlite3").verbose();

const db = new sqlite3.Database("./blog.db", (err) => {
  if (err) console.error("DB error:", err.message);
  else console.log("DB connected");
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

module.exports = db;
