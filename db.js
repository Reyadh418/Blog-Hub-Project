require('dotenv').config();
const { Pool } = require('pg');

const DATABASE_URL = (process.env.DATABASE_URL || '').toString().trim();

// Create connection pool from DATABASE_URL env var (Supabase/Render)
const pool = new Pool({
  connectionString: DATABASE_URL || undefined,
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

// Initialize schema on startup (exported as promise so server can await it)
const initPromise = (async () => {
  try {
    if (!DATABASE_URL) {
      throw new Error('DATABASE_URL is missing. Set DATABASE_URL in your environment (.env) before starting the server.');
    }

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
        is_author_verified INTEGER DEFAULT 0,
        author_verified_by_admin_id INTEGER,
        author_verified_at TIMESTAMP,
        verification_code TEXT DEFAULT '',
        verification_code_expires TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_author_verified INTEGER DEFAULT 0`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS author_verified_by_admin_id INTEGER`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS author_verified_at TIMESTAMP`);

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

    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_audit_logs (
        id SERIAL PRIMARY KEY,
        actor_admin_id INTEGER NOT NULL,
        target_user_id INTEGER,
        action_type TEXT NOT NULL,
        details TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (actor_admin_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (target_user_id) REFERENCES users(id) ON DELETE SET NULL
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
      'CREATE INDEX IF NOT EXISTS idx_users_is_author_verified ON users(is_author_verified)',
      'CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)',
      'CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id)',
      'CREATE INDEX IF NOT EXISTS idx_comments_user_id ON comments(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_reactions_post_id ON reactions(post_id)',
      'CREATE INDEX IF NOT EXISTS idx_reactions_user_id ON reactions(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_bookmarks_user_id ON bookmarks(user_id)',
      'CREATE INDEX IF NOT EXISTS idx_bookmarks_post_id ON bookmarks(post_id)',
      'CREATE INDEX IF NOT EXISTS idx_notifications_user_id_created_at ON notifications(user_id, created_at DESC)',
      'CREATE INDEX IF NOT EXISTS idx_admin_audit_actor_created_at ON admin_audit_logs(actor_admin_id, created_at DESC)',
      'CREATE INDEX IF NOT EXISTS idx_admin_audit_created_at ON admin_audit_logs(created_at DESC)',
    ];

    for (const idx of indexes) {
      await pool.query(idx);
    }

    // Note: Admin hierarchy is now managed entirely by ensureAdminUser() in server.js
    // No hardcoded usernames here — admin bootstrap reads from env vars

    console.log('[db] Schema initialization complete');
  } catch (err) {
    console.error('[db] Schema initialization error:', err);
    throw err; // Let the caller know init failed
  }
})();

// Export wrapper functions to match sqlite3 interface used in server.js
module.exports = {
  initPromise, // await this before starting the server
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
    // Support RETURNING id for inserts
    const lastID = result.rows && result.rows.length > 0 && result.rows[0].id != null
      ? result.rows[0].id
      : null;
    return { lastID, changes: result.rowCount };
  },
  pool, // Export pool for direct access if needed
};
