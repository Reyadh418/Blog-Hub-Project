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

// Ensure there's a concrete user row for the admin so actions that require user_id (e.g., comments/reactions) work.
async function ensureAdminUser() {
  // Use a stable username/email to avoid duplicates.
  const adminUsername = "@admin";
  const adminEmail = "admin@example.local";
  const existing = await dbGet("SELECT id, username FROM users WHERE username = ?", [adminUsername]);
  if (existing) return existing;

  // Insert a placeholder password hash; admin authentication is still via env vars.
  const placeholderHash = hashPassword("admin_placeholder");
  const created = await dbRun(
    "INSERT INTO users (username, email, password_hash, full_name) VALUES (?, ?, ?, ?)",
    [adminUsername, adminEmail, placeholderHash, "Site Admin"]
  );
  return { id: created.lastID, username: adminUsername };
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
      const adminUser = await ensureAdminUser();

      req.session.isAdmin = true;
      req.session.userRole = "admin";
      req.session.userId = adminUser.id; // so admin actions needing user_id work
      req.session.username = adminUser.username;

      // Save session before responding to preserve login
      req.session.save((err) => {
        if (err) return res.status(500).json({ error: "Failed to create session" });
        res.json({ ok: true, userId: adminUser.id, username: adminUser.username });
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
      return res.json({ isAdmin: true, userRole: "admin", userId: req.session.userId || null, username: req.session.username || "@admin" });
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
      return res.json({ isAdmin: true, userId: req.session.userId || null, username: req.session.username || "@admin" });
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
        p.is_flagged,
        CASE 
          WHEN p.author_id IS NULL THEN '@admin'
          ELSE u.username
        END as author_name,
        CASE 
          WHEN p.author_id IS NULL THEN 1
          ELSE 0
        END as is_admin_post,
        COALESCE((SELECT COUNT(*) FROM comments WHERE post_id = p.id), 0) as comment_count,
        COALESCE((SELECT COUNT(*) FROM reactions WHERE post_id = p.id AND reaction_type = 'useful'), 0) as useful_count,
        COALESCE((SELECT COUNT(*) FROM reactions WHERE post_id = p.id AND reaction_type = 'notuseful'), 0) as notuseful_count
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
        p.is_flagged,
        CASE 
          WHEN p.author_id IS NULL THEN '@admin'
          ELSE u.username
        END as author_name,
        CASE 
          WHEN p.author_id IS NULL THEN 1
          ELSE 0
        END as is_admin_post,
        COALESCE((SELECT COUNT(*) FROM comments WHERE post_id = p.id), 0) as comment_count,
        COALESCE((SELECT COUNT(*) FROM reactions WHERE post_id = p.id AND reaction_type = 'useful'), 0) as useful_count,
        COALESCE((SELECT COUNT(*) FROM reactions WHERE post_id = p.id AND reaction_type = 'notuseful'), 0) as notuseful_count
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
// Edit a post with permission checks
// Admin can only edit their own posts (author_id IS NULL)
// Users can only edit their own posts (author_id = userId)
app.put("/api/posts/:id", async (req, res, next) => {
  try {
    if (!req.session.isAdmin && !req.session.userId) {
      return res.status(401).json({ error: "Authentication required" });
    }

    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid post id" });

    // Get the post to check ownership
    const post = await dbGet("SELECT id, author_id FROM posts WHERE id = ?", [id]);
    if (!post) return res.status(404).json({ error: "Post not found" });

    // Permission checks
    if (req.session.isAdmin) {
      // Admin can only edit posts they created (author_id IS NULL)
      if (post.author_id !== null) {
        return res.status(403).json({ error: "Admin can only edit their own posts" });
      }
    } else {
      // User can only edit their own posts
      if (post.author_id !== req.session.userId) {
        return res.status(403).json({ error: "You can only edit your own posts" });
      }
    }

    const title = (req.body.title || "").toString().trim();
    const body = (req.body.body || "").toString().trim();
    let tags = req.body.tags || [];
    if (!Array.isArray(tags)) {
      tags = tags.toString().split(',').map(s => s.trim()).filter(Boolean);
    }

    if (!title || !body) return res.status(400).json({ error: "Title and body are required" });

    const result = await dbRun("UPDATE posts SET title = ?, body = ?, tags = ? WHERE id = ?", [title, body, JSON.stringify(tags), id]);
    if (!result.changes) return res.status(404).json({ error: "Post not found" });

    const rows = await dbAll(`
      SELECT p.id, p.title, p.body, p.created_at, p.tags, p.is_flagged,
        CASE WHEN p.author_id IS NULL THEN '@admin' ELSE u.username END as author_name
      FROM posts p
      LEFT JOIN users u ON p.author_id = u.id
      WHERE p.id = ?
    `, [id]);
    res.json(rows[0]);
  } catch (err) {
    next(err);
  }
});

// Delete a post with permission checks
// Admin can delete any post
// Users can only delete their own posts
app.delete("/api/posts/:id", async (req, res, next) => {
  try {
    if (!req.session.isAdmin && !req.session.userId) {
      return res.status(401).json({ error: "Authentication required" });
    }

    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid post id" });

    // Get the post to check ownership
    const post = await dbGet("SELECT id, author_id FROM posts WHERE id = ?", [id]);
    if (!post) return res.status(404).json({ error: "Post not found" });

    // Permission checks
    if (!req.session.isAdmin) {
      // User can only delete their own posts
      if (post.author_id !== req.session.userId) {
        return res.status(403).json({ error: "You can only delete your own posts" });
      }
    }
    // Admin can delete any post (no additional check needed)

    const result = await dbRun("DELETE FROM posts WHERE id = ?", [id]);
    if (!result.changes) return res.status(404).json({ error: "Post not found" });

    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// Flag/unflag a post (admin only)
app.patch("/api/posts/:id/flag", async (req, res, next) => {
  try {
    if (!req.session.isAdmin) {
      return res.status(403).json({ error: "Only admins can flag posts" });
    }

    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid post id" });

    const flagged = req.body.flag === true ? 1 : 0;

    // Check if post exists
    const post = await dbGet("SELECT id FROM posts WHERE id = ?", [id]);
    if (!post) return res.status(404).json({ error: "Post not found" });

    const result = await dbRun("UPDATE posts SET is_flagged = ? WHERE id = ?", [flagged, id]);
    if (!result.changes) return res.status(404).json({ error: "Post not found" });

    const updated = await dbGet(`
      SELECT p.id, p.is_flagged,
        CASE WHEN p.author_id IS NULL THEN '@admin' ELSE u.username END as author_name
      FROM posts p
      LEFT JOIN users u ON p.author_id = u.id
      WHERE p.id = ?
    `, [id]);

    res.json({ ok: true, is_flagged: flagged, post: updated });
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
      SELECT p.id, p.title, p.body, p.created_at, p.tags, p.is_flagged,
        CASE WHEN p.author_id IS NULL THEN '@admin' ELSE u.username END as author_name,
        CASE WHEN p.author_id IS NULL THEN 1 ELSE 0 END as is_admin_post
      FROM posts p LEFT JOIN users u ON p.author_id = u.id WHERE p.id = ?
    `, [result.lastID]);

    res.status(201).json(created);
  } catch (err) {
    next(err);
  }
});

// --------- COMMENTS ENDPOINTS ---------
// Get all comments for a post
app.get('/api/posts/:postId/comments', async (req, res, next) => {
  try {
    const postId = Number(req.params.postId);
    if (!Number.isInteger(postId) || postId <= 0) return res.status(400).json({ error: "Invalid post id" });

    const comments = await dbAll(`
      SELECT c.id, c.post_id, c.user_id, c.body, c.created_at, c.updated_at, u.username
      FROM comments c
      JOIN users u ON c.user_id = u.id
      WHERE c.post_id = ?
      ORDER BY c.created_at DESC
    `, [postId]);

    res.json(comments);
  } catch (err) {
    next(err);
  }
});

// Create a comment (requires auth)
app.post('/api/posts/:postId/comments', requireAuth, async (req, res, next) => {
  try {
    const postId = Number(req.params.postId);
    if (!Number.isInteger(postId) || postId <= 0) return res.status(400).json({ error: "Invalid post id" });

    const body = (req.body.body || "").toString().trim();
    if (!body) return res.status(400).json({ error: "Comment body is required" });

    // Check post exists
    const post = await dbGet("SELECT id FROM posts WHERE id = ?", [postId]);
    if (!post) return res.status(404).json({ error: "Post not found" });

    const result = await dbRun(
      "INSERT INTO comments (post_id, user_id, body) VALUES (?, ?, ?)",
      [postId, req.session.userId, body]
    );

    const comment = await dbGet(`
      SELECT c.id, c.post_id, c.user_id, c.body, c.created_at, c.updated_at, u.username
      FROM comments c
      JOIN users u ON c.user_id = u.id
      WHERE c.id = ?
    `, [result.lastID]);

    res.status(201).json(comment);
  } catch (err) {
    next(err);
  }
});

// Update a comment (owner only)
app.put('/api/comments/:commentId', async (req, res, next) => {
  try {
    if (!req.session.userId) return res.status(401).json({ error: "Authentication required" });

    const commentId = Number(req.params.commentId);
    if (!Number.isInteger(commentId) || commentId <= 0) return res.status(400).json({ error: "Invalid comment id" });

    const body = (req.body.body || "").toString().trim();
    if (!body) return res.status(400).json({ error: "Comment body is required" });

    // Check comment exists and user owns it
    const comment = await dbGet("SELECT id, user_id FROM comments WHERE id = ?", [commentId]);
    if (!comment) return res.status(404).json({ error: "Comment not found" });

    if (comment.user_id !== req.session.userId) {
      return res.status(403).json({ error: "You can only edit your own comments" });
    }

    await dbRun(
      "UPDATE comments SET body = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
      [body, commentId]
    );

    const updated = await dbGet(`
      SELECT c.id, c.post_id, c.user_id, c.body, c.created_at, c.updated_at, u.username
      FROM comments c
      JOIN users u ON c.user_id = u.id
      WHERE c.id = ?
    `, [commentId]);

    res.json(updated);
  } catch (err) {
    next(err);
  }
});

// Delete a comment (owner or admin)
app.delete('/api/comments/:commentId', async (req, res, next) => {
  try {
    if (!req.session.userId && !req.session.isAdmin) {
      return res.status(401).json({ error: "Authentication required" });
    }

    const commentId = Number(req.params.commentId);
    if (!Number.isInteger(commentId) || commentId <= 0) return res.status(400).json({ error: "Invalid comment id" });

    const comment = await dbGet("SELECT id, user_id FROM comments WHERE id = ?", [commentId]);
    if (!comment) return res.status(404).json({ error: "Comment not found" });

    // User can only delete their own, admin can delete any
    if (!req.session.isAdmin && comment.user_id !== req.session.userId) {
      return res.status(403).json({ error: "You can only delete your own comments" });
    }

    const result = await dbRun("DELETE FROM comments WHERE id = ?", [commentId]);
    if (!result.changes) return res.status(404).json({ error: "Comment not found" });

    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// --------- REACTIONS ENDPOINTS ---------
// Get reaction counts for a post
app.get('/api/posts/:postId/reactions', async (req, res, next) => {
  try {
    const postId = Number(req.params.postId);
    if (!Number.isInteger(postId) || postId <= 0) return res.status(400).json({ error: "Invalid post id" });

    const useful = await dbGet(
      "SELECT COUNT(*) as count FROM reactions WHERE post_id = ? AND reaction_type = 'useful'",
      [postId]
    );
    const notUseful = await dbGet(
      "SELECT COUNT(*) as count FROM reactions WHERE post_id = ? AND reaction_type = 'notuseful'",
      [postId]
    );

    // Get user's reaction if logged in
    let userReaction = null;
    if (req.session.userId) {
      const reaction = await dbGet(
        "SELECT reaction_type FROM reactions WHERE post_id = ? AND user_id = ?",
        [postId, req.session.userId]
      );
      if (reaction) userReaction = reaction.reaction_type;
    }

    res.json({
      useful: useful.count,
      notUseful: notUseful.count,
      userReaction
    });
  } catch (err) {
    next(err);
  }
});

// Add or update a reaction (requires auth)
app.post('/api/posts/:postId/reactions', requireAuth, async (req, res, next) => {
  try {
    const postId = Number(req.params.postId);
    if (!Number.isInteger(postId) || postId <= 0) return res.status(400).json({ error: "Invalid post id" });

    const reactionType = (req.body.reaction_type || "").toString().toLowerCase();
    if (!['useful', 'notuseful'].includes(reactionType)) {
      return res.status(400).json({ error: "Reaction type must be 'useful' or 'notuseful'" });
    }

    // Check post exists
    const post = await dbGet("SELECT id FROM posts WHERE id = ?", [postId]);
    if (!post) return res.status(404).json({ error: "Post not found" });

    // Check if user already has a reaction
    const existing = await dbGet(
      "SELECT id, reaction_type FROM reactions WHERE post_id = ? AND user_id = ?",
      [postId, req.session.userId]
    );

    if (existing) {
      if (existing.reaction_type === reactionType) {
        // Same reaction, no change
        return res.status(400).json({ error: "You already have this reaction" });
      }
      // Update existing reaction to new type
      await dbRun(
        "UPDATE reactions SET reaction_type = ? WHERE post_id = ? AND user_id = ?",
        [reactionType, postId, req.session.userId]
      );
    } else {
      // Insert new reaction
      await dbRun(
        "INSERT INTO reactions (post_id, user_id, reaction_type) VALUES (?, ?, ?)",
        [postId, req.session.userId, reactionType]
      );
    }

    // Return updated counts and user's reaction
    const useful = await dbGet(
      "SELECT COUNT(*) as count FROM reactions WHERE post_id = ? AND reaction_type = 'useful'",
      [postId]
    );
    const notUseful = await dbGet(
      "SELECT COUNT(*) as count FROM reactions WHERE post_id = ? AND reaction_type = 'notuseful'",
      [postId]
    );

    res.json({
      ok: true,
      useful: useful.count,
      notUseful: notUseful.count,
      userReaction: reactionType
    });
  } catch (err) {
    next(err);
  }
});

// Remove a reaction
app.delete('/api/posts/:postId/reactions', requireAuth, async (req, res, next) => {
  try {
    const postId = Number(req.params.postId);
    if (!Number.isInteger(postId) || postId <= 0) return res.status(400).json({ error: "Invalid post id" });

    const result = await dbRun(
      "DELETE FROM reactions WHERE post_id = ? AND user_id = ?",
      [postId, req.session.userId]
    );

    if (!result.changes) return res.status(404).json({ error: "Reaction not found" });

    // Return updated counts
    const useful = await dbGet(
      "SELECT COUNT(*) as count FROM reactions WHERE post_id = ? AND reaction_type = 'useful'",
      [postId]
    );
    const notUseful = await dbGet(
      "SELECT COUNT(*) as count FROM reactions WHERE post_id = ? AND reaction_type = 'notuseful'",
      [postId]
    );

    res.json({
      ok: true,
      useful: useful.count,
      notUseful: notUseful.count,
      userReaction: null
    });
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
        SELECT p.id, p.title, p.body, p.created_at, p.tags, p.is_flagged,
          CASE WHEN p.author_id IS NULL THEN '@admin' ELSE u.username END as author_name,
          CASE WHEN p.author_id IS NULL THEN 1 ELSE 0 END as is_admin_post,
          COALESCE((SELECT COUNT(*) FROM comments WHERE post_id = p.id), 0) as comment_count,
          COALESCE((SELECT COUNT(*) FROM reactions WHERE post_id = p.id AND reaction_type = 'useful'), 0) as useful_count,
          COALESCE((SELECT COUNT(*) FROM reactions WHERE post_id = p.id AND reaction_type = 'notuseful'), 0) as notuseful_count
        FROM posts p
        LEFT JOIN users u ON p.author_id = u.id
        ORDER BY p.id DESC
      `);
      return res.json(rows);
    }

    const like = `%${q}%`;
    const rows = await dbAll(
      `
        SELECT p.id, p.title, p.body, p.created_at, p.tags, p.is_flagged,
          CASE WHEN p.author_id IS NULL THEN '@admin' ELSE u.username END as author_name,
          CASE WHEN p.author_id IS NULL THEN 1 ELSE 0 END as is_admin_post,
          COALESCE((SELECT COUNT(*) FROM comments WHERE post_id = p.id), 0) as comment_count,
          COALESCE((SELECT COUNT(*) FROM reactions WHERE post_id = p.id AND reaction_type = 'useful'), 0) as useful_count,
          COALESCE((SELECT COUNT(*) FROM reactions WHERE post_id = p.id AND reaction_type = 'notuseful'), 0) as notuseful_count
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
