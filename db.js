require('dotenv').config();
const { Pool } = require('pg');

// Create connection pool from DATABASE_URL env var (Supabase/Render)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  statement_timeout: 30000,
  idle_in_transaction_session_timeout: 30000,
  // Force IPv4 on Render (free tier doesn't support IPv6)
  family: 4,
});

pool.on('error', (err) => {
  console.error('[db] Unexpected error on idle client', err);
});

pool.on('connect', () => {
  console.log('[db] PostgreSQL connected');
});

// Initialize schema on startup
(async () => {
  try {
    // Create tables with PostgreSQL syntax
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        is_super_admin INTEGER DEFAULT 0,
        is_promoted_admin INTEGER DEFAULT 0,
        avatar TEXT DEFAULT '',
        full_name TEXT DEFAULT '',
        bio TEXT DEFAULT '',
        email_verified INTEGER DEFAULT 0,
        verification_code TEXT DEFAULT '',
        verification_code_expires TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS posts (
        id SERIAL PRIMARY KEY,
        author_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        tags TEXT DEFAULT '',
        is_flagged INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (author_id) REFERENCES users(id)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS comments (
        id SERIAL PRIMARY KEY,
        post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        body TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS reactions (
        id SERIAL PRIMARY KEY,
        post_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        reaction_type TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(post_id, user_id)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS bookmarks (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        post_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
        UNIQUE(user_id, post_id)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        post_id INTEGER,
        type TEXT NOT NULL,
        message TEXT NOT NULL,
        is_read INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
      )
    `);

    // Create indexes
    const indexes = [
      'CREATE INDEX IF NOT EXISTS idx_posts_author_id ON posts(author_id)',
      'CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts(created_at DESC)',
      'CREATE INDEX IF NOT EXISTS idx_posts_is_flagged ON posts(is_flagged)',
      'CREATE INDEX IF NOT EXISTS idx_posts_title ON posts(title)',
      'CREATE INDEX IF NOT EXISTS idx_posts_tags ON posts(tags)',
      'CREATE INDEX IF NOT EXISTS idx_users_is_admin ON users(is_admin)',
      'CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)',
      'CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id)',
      'CREATE INDEX IF NOT EXISTS idx_comments_user_id ON comments(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_reactions_post_id ON reactions(post_id)',
      'CREATE INDEX IF NOT EXISTS idx_reactions_user_id ON reactions(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_bookmarks_user_id ON bookmarks(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_bookmarks_post_id ON bookmarks(post_id)',
      'CREATE INDEX IF NOT EXISTS idx_notifications_user_id_created_at ON notifications(user_id, created_at DESC)',
    ];

    for (const idx of indexes) {
      await pool.query(idx);
    }

    // Enforce admin hierarchy on startup
    await pool.query(
      `UPDATE users SET is_super_admin = 0, is_promoted_admin = CASE WHEN is_admin = 1 THEN 1 ELSE 0 END WHERE username != $1 AND is_super_admin = 1`,
      ['admin']
    );
    await pool.query(
      `UPDATE users SET is_admin = 1, is_super_admin = 1, is_promoted_admin = 0 WHERE username = $1`,
      ['admin']
    );
    await pool.query(
      `UPDATE users SET is_admin = 1, is_super_admin = 0, is_promoted_admin = 1 WHERE username = $1`,
      ['reyadhasan']
    );

    const superAdminResult = await pool.query('SELECT username FROM users WHERE is_super_admin = 1 LIMIT 1');
    if (superAdminResult.rows.length > 0) {
      console.log('[db] Super Admin:', superAdminResult.rows[0].username);
    }

    console.log('[db] Schema initialization complete');
  } catch (err) {
    console.error('[db] Schema initialization error:', err.message);
  }
})();

// Export wrapper functions to match sqlite3 interface used in server.js
module.exports = {
  all: async (sql, params = []) => {
    const result = await pool.query(sql, params);
    return result.rows;
  },
  get: async (sql, params = []) => {
    const result = await pool.query(sql, params);
    return result.rows[0] || null;
  },
  run: async (sql, params = []) => {
    const result = await pool.query(sql, params);
    return { lastID: result.rows[0]?.id || null, changes: result.rowCount };
  },
  pool, // Export pool for direct access if needed
};
