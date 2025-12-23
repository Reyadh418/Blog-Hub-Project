require("dotenv").config({ path: "admin.env" });

const express = require("express");
const path = require("path");
const session = require("express-session");
const crypto = require("crypto");

const db = require("./db");

const app = express();

// Parse JSON body (so POST requests work)
app.use(express.json());

// In production behind a proxy, honor secure cookies when NODE_ENV=production
if (process.env.TRUST_PROXY === "1") app.set("trust proxy", 1);

app.use(
  session({
    name: process.env.SESSION_NAME || "sid",
    secret: process.env.SESSION_SECRET || "dev_secret_change_me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
  })
);

// Serve frontend files from /public
app.use(express.static(path.join(__dirname, "public")));

// --------------------
// Helpers
// --------------------

function hashPassword(password) {
  return crypto.createHash("sha256").update(password + process.env.PASSWORD_SALT || "default_salt").digest("hex");
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  return res.status(403).json({ error: "Admin only" });
}

function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.status(401).json({ error: "Authentication required" });
}

const dbAll = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      // normalize tags into arrays
      const normalized = rows.map(r => {
        if (r.tags == null) r.tags = '';
        try {
          r.tags = JSON.parse(r.tags);
        } catch (e) {
          // fallback: comma-separated
          r.tags = (r.tags || '').toString().split(',').map(s => s.trim()).filter(Boolean);
        }
        return r;
      });
      resolve(normalized);
    });
  });

const dbRun = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });

const dbGet = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });

// --------------------
// API routes
// --------------------

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime(), now: new Date().toISOString() });
});

// User Registration
app.post("/api/auth/register", async (req, res, next) => {
  try {
    const username = (req.body.username || "").toString().trim().toLowerCase();
    const email = (req.body.email || "").toString().trim().toLowerCase();
    const password = (req.body.password || "").toString();
    const fullName = (req.body.fullName || "").toString().trim();

    // Validation
    if (!username || username.length < 3) return res.status(400).json({ error: "Username must be at least 3 characters" });
    if (!email || !email.includes("@")) return res.status(400).json({ error: "Valid email required" });
    if (!password || password.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });

    // Check if user exists
    const existing = await dbGet("SELECT id FROM users WHERE username = ? OR email = ?", [username, email]);
    if (existing) return res.status(409).json({ error: "Username or email already exists" });

    // Hash password and create user
    const passwordHash = hashPassword(password);
    const result = await dbRun("INSERT INTO users (username, email, password_hash, full_name) VALUES (?, ?, ?, ?)", 
      [username, email, passwordHash, fullName]);

    // Auto-login after registration
    req.session.userId = result.lastID;
    req.session.username = username;
    req.session.userRole = "user";

    // Save session before responding to preserve login
    req.session.save((err) => {
      if (err) return res.status(500).json({ error: "Failed to create session" });
      res.status(201).json({ ok: true, userId: result.lastID, username });
    });
  } catch (err) {
    next(err);
  }
});

// User Login
app.post("/api/auth/login", async (req, res, next) => {
  try {
    const username = (req.body.username || "").toString().trim().toLowerCase();
    const password = (req.body.password || "").toString();

    if (!username || !password) return res.status(400).json({ error: "Username and password required" });

    const user = await dbGet("SELECT id, username, password_hash FROM users WHERE username = ?", [username]);
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const passwordHash = hashPassword(password);
    if (user.password_hash !== passwordHash) return res.status(401).json({ error: "Invalid credentials" });

    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.userRole = "user";

    // Save session before responding to preserve login
    req.session.save((err) => {
      if (err) return res.status(500).json({ error: "Failed to create session" });
      res.json({ ok: true, userId: user.id, username: user.username });
    });
  } catch (err) {
    next(err);
  }
});

// Admin Login (existing)
app.post("/api/admin/login", async (req, res, next) => {
  try {
    const username = (req.body.username || "").toString();
    const password = (req.body.password || "").toString();

    if (!username || !password) return res.status(400).json({ error: "username and password required" });

    if (username === process.env.ADMIN_USER && password === process.env.ADMIN_PASS) {
      req.session.isAdmin = true;
      req.session.userRole = "admin";
      // Save session before responding to preserve login
      req.session.save((err) => {
        if (err) return res.status(500).json({ error: "Failed to create session" });
        res.json({ ok: true });
      });
      return;
    }

    return res.status(401).json({ ok: false, error: "Invalid credentials" });
  } catch (err) {
    next(err);
  }
});

// Logout (handles both user and admin)
app.post("/api/auth/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: "Failed to destroy session" });
    res.json({ ok: true });
  });
});

// Get current user (replaces /api/me)
app.get("/api/auth/me", async (req, res, next) => {
  try {
    if (req.session.isAdmin) {
      return res.json({ isAdmin: true, userRole: "admin" });
    }
    if (req.session.userId) {
      const user = await dbGet("SELECT id, username, full_name, email, bio FROM users WHERE id = ?", [req.session.userId]);
      return res.json({ id: user.id, userId: user.id, username: user.username, full_name: user.full_name, fullName: user.full_name, email: user.email, bio: user.bio, userRole: "user", isAdmin: false });
    }
    res.json({ isAdmin: false, userId: null, userRole: null });
  } catch (err) {
    next(err);
  }
});

// Keep /api/me for backwards compatibility
app.get("/api/me", async (req, res, next) => {
  try {
    if (req.session.isAdmin) {
      return res.json({ isAdmin: true });
    }
    if (req.session.userId) {
      const user = await dbGet("SELECT id, username, full_name FROM users WHERE id = ?", [req.session.userId]);
      return res.json({ isAdmin: false, userId: user.id, username: user.username });
    }
    res.json({ isAdmin: false });
  } catch (err) {
    next(err);
  }
});

// Get user profile
app.get("/api/users/:id", async (req, res, next) => {
  try {
    const userId = Number(req.params.id);
    if (!Number.isInteger(userId) || userId <= 0) return res.status(400).json({ error: "Invalid user id" });

    const user = await dbGet("SELECT id, username, email, full_name, bio, created_at FROM users WHERE id = ?", [userId]);
    if (!user) return res.status(404).json({ error: "User not found" });

    // Get user's posts
    const posts = await dbAll("SELECT id, title, body, created_at FROM posts WHERE author_id = ? ORDER BY created_at DESC", [userId]);

    res.json({ id: user.id, username: user.username, email: user.email, full_name: user.full_name, bio: user.bio, created_at: user.created_at, posts });
  } catch (err) {
    next(err);
  }
});

// Update user profile (requires auth)
app.put("/api/auth/profile", requireAuth, async (req, res, next) => {
  try {
    const fullName = (req.body.full_name || req.body.fullName || "").toString().trim();
    const email = (req.body.email || "").toString().trim().toLowerCase();
    const bio = (req.body.bio || "").toString().trim();

    // Validate email if provided
    if (email && !email.includes("@")) {
      return res.status(400).json({ error: "Valid email required" });
    }

    // Check if email is already in use by another user
    if (email) {
      const existingEmail = await dbGet("SELECT id FROM users WHERE email = ? AND id != ?", [email, req.session.userId]);
      if (existingEmail) {
        return res.status(409).json({ error: "Email already in use" });
      }
    }

    // Update user profile
    const updateFields = [];
    const updateParams = [];
    
    if (fullName) {
      updateFields.push("full_name = ?");
      updateParams.push(fullName);
    }
    if (email) {
      updateFields.push("email = ?");
      updateParams.push(email);
    }
    if (bio !== undefined) {
      updateFields.push("bio = ?");
      updateParams.push(bio);
    }

    if (updateFields.length > 0) {
      updateParams.push(req.session.userId);
      const updateSQL = `UPDATE users SET ${updateFields.join(", ")} WHERE id = ?`;
      await dbRun(updateSQL, updateParams);
    }

    const user = await dbGet("SELECT id, username, full_name, email, bio FROM users WHERE id = ?", [req.session.userId]);

    res.json({ id: user.id, username: user.username, full_name: user.full_name, email: user.email, bio: user.bio });
  } catch (err) {
    next(err);
  }
});

app.get("/api/posts", async (req, res, next) => {
  try {
    const rows = await dbAll(`
      SELECT 
        p.id, 
        p.title, 
        p.body, 
        p.created_at, 
        p.author_id, 
        p.tags,
        CASE 
          WHEN p.author_id IS NULL THEN '@admin'
          ELSE u.username
        END as author_name,
        CASE 
          WHEN p.author_id IS NULL THEN 1
          ELSE 0
        END as is_admin_post
      FROM posts p
      LEFT JOIN users u ON p.author_id = u.id
      ORDER BY p.id DESC
    `);
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

app.get("/api/posts/:id", async (req, res, next) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ error: "Invalid post id" });
    }

    const rows = await dbAll(`
      SELECT 
        p.id, 
        p.title, 
        p.body, 
        p.created_at, 
        p.author_id,
        p.tags,
        CASE 
          WHEN p.author_id IS NULL THEN '@admin'
          ELSE u.username
        END as author_name,
        CASE 
          WHEN p.author_id IS NULL THEN 1
          ELSE 0
        END as is_admin_post
      FROM posts p
      LEFT JOIN users u ON p.author_id = u.id
      WHERE p.id = ?
    `, [id]);

    if (rows.length === 0) {
      return res.status(404).json({ error: "Post not found" });
    }

    res.json(rows[0]);
  } catch (err) {
    next(err);
  }
});

// Update a post (admin only)
app.put("/api/posts/:id", requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid post id" });

    const title = (req.body.title || "").toString().trim();
    const body = (req.body.body || "").toString().trim();
    let tags = req.body.tags || [];
    if (!Array.isArray(tags)) {
      // allow comma-separated string
      tags = tags.toString().split(',').map(s => s.trim()).filter(Boolean);
    }

    if (!title || !body) return res.status(400).json({ error: "Title and body are required" });

    const result = await dbRun("UPDATE posts SET title = ?, body = ?, tags = ? WHERE id = ?", [title, body, JSON.stringify(tags), id]);
    if (!result.changes) return res.status(404).json({ error: "Post not found" });

    const rows = await dbAll("SELECT id, title, body, created_at, tags FROM posts WHERE id = ?", [id]);
    res.json(rows[0]);
  } catch (err) {
    next(err);
  }
});

// Delete a post (admin only)
app.delete("/api/posts/:id", requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid post id" });

    const result = await dbRun("DELETE FROM posts WHERE id = ?", [id]);
    if (!result.changes) return res.status(404).json({ error: "Post not found" });

    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});


app.post("/api/posts", async (req, res, next) => {
  try {
    // Allow both admin and authenticated users to create posts
    if (!req.session.isAdmin && !req.session.userId) return res.status(401).json({ error: "Authentication required" });

    // For admins, store NULL in author_id so admin posts are distinct
    const authorId = req.session.isAdmin ? null : req.session.userId;

    const title = (req.body.title || "").toString().trim();
    const body = (req.body.body || "").toString().trim();
    let tags = req.body.tags || [];
    if (!Array.isArray(tags)) {
      tags = tags.toString().split(',').map(s => s.trim()).filter(Boolean);
    }

    if (!title || !body) return res.status(400).json({ error: "Title and body are required" });

    const result = await dbRun("INSERT INTO posts (author_id, title, body, tags) VALUES (?, ?, ?, ?)", 
      [authorId, title, body, JSON.stringify(tags)]);

    // Return created resource including author info
    const created = await dbGet(`
      SELECT p.id, p.title, p.body, p.created_at, p.tags, 
        CASE WHEN p.author_id IS NULL THEN '@admin' ELSE u.username END as author_name,
        CASE WHEN p.author_id IS NULL THEN 1 ELSE 0 END as is_admin_post
      FROM posts p LEFT JOIN users u ON p.author_id = u.id WHERE p.id = ?
    `, [result.lastID]);

    res.status(201).json(created);
  } catch (err) {
    next(err);
  }
});

// Search endpoint: search by title/body/tags (case-insensitive LIKE)
app.get('/api/search', async (req, res, next) => {
  try {
    const q = (req.query.q || '').toString().trim();
    if (!q) {
      // if no query, return all posts
      const rows = await dbAll(`
        SELECT p.id, p.title, p.body, p.created_at, p.tags,
          CASE WHEN p.author_id IS NULL THEN '@admin' ELSE u.username END as author_name,
          CASE WHEN p.author_id IS NULL THEN 1 ELSE 0 END as is_admin_post
        FROM posts p
        LEFT JOIN users u ON p.author_id = u.id
        ORDER BY p.id DESC
      `);
      return res.json(rows);
    }

    const like = `%${q}%`;
    const rows = await dbAll(
      `
        SELECT p.id, p.title, p.body, p.created_at, p.tags,
          CASE WHEN p.author_id IS NULL THEN '@admin' ELSE u.username END as author_name,
          CASE WHEN p.author_id IS NULL THEN 1 ELSE 0 END as is_admin_post
        FROM posts p
        LEFT JOIN users u ON p.author_id = u.id
        WHERE p.title LIKE ? OR p.body LIKE ? OR p.tags LIKE ?
        ORDER BY p.id DESC
      `,
      [like, like, like]
    );

    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// Basic homepage route (optional)
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Centralized error handler
app.use((err, req, res, next) => {
  console.error(err && err.stack ? err.stack : err);
  res.status(500).json({ error: err && err.message ? err.message : 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
