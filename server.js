// dotenv removed; admin credentials are DB-backed now.

const express = require("express");
const path = require("path");
const session = require("express-session");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const db = require("./db");

const app = express();

// Parse JSON body (so POST requests work) with sensible limits
app.use(express.json({ limit: "512kb" }));

// In production behind a proxy, honor secure cookies when NODE_ENV=production
if (process.env.TRUST_PROXY === "1") app.set("trust proxy", 1);

const SESSION_SECRET = process.env.SESSION_SECRET;
if (process.env.NODE_ENV === "production" && (!SESSION_SECRET || SESSION_SECRET.length < 16)) {
  console.error("[security] SESSION_SECRET is required in production and must be at least 16 characters. Set a strong random value.");
  process.exit(1);
}
if (!SESSION_SECRET || SESSION_SECRET.length < 16) {
  console.warn("[security] SESSION_SECRET is weak or missing; set a strong value in production.");
}

app.use(
  session({
    name: process.env.SESSION_NAME || "sid",
    secret: SESSION_SECRET || "dev_secret_change_me", // development fallback only
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 1000 * 60 * 60 * 12, // 12 hours
    },
  })
);

// Lightweight security headers (CSP kept permissive due to inline assets)
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self' data:; frame-ancestors 'none';"
  );
  if (process.env.NODE_ENV === "production") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  next();
});

// CSRF token provisioning
app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(24).toString("hex");
  }
  res.setHeader("x-csrf-token", req.session.csrfToken);
  next();
});

// Serve frontend files from /public
app.use(express.static(path.join(__dirname, "public")));

// Apply generic write limiter to all mutating requests
app.use((req, res, next) => {
  if (CSRF_METHODS.has(req.method)) return writeLimiter(req, res, next);
  return next();
});

// CSRF protection for mutating requests
app.use(csrfGuard);

// --------------------
// Helpers
// --------------------

const ALLOWED_AVATARS = [
  "aurora",
  "sunset",
  "wave",
  "forest",
  "midnight",
  "plum",
  "citrus",
  "ember",
  "mint",
];

function safeAvatar(value) {
  if (!value) return "";
  return ALLOWED_AVATARS.includes(value) ? value : "";
}

function defaultAvatar() {
  return ALLOWED_AVATARS[0];
}

const BCRYPT_ROUNDS = (() => {
  const val = parseInt(process.env.BCRYPT_ROUNDS || "12", 10);
  if (Number.isNaN(val) || val < 8) return 12;
  if (val > 14) return 14;
  return val;
})();

async function hashPassword(password) {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

async function verifyPassword(password, storedHash, userId) {
  if (!storedHash) return false;
  // bcrypt path
  if (storedHash.startsWith("$2")) {
    return bcrypt.compare(password, storedHash);
  }
  // legacy sha256 path for existing users; migrate when validated
  const legacySalt = process.env.PASSWORD_SALT !== undefined ? process.env.PASSWORD_SALT : "undefined";
  const legacyHash = crypto.createHash("sha256").update(`${password}${legacySalt}`).digest("hex");
  const ok = legacyHash === storedHash;
  if (ok && userId) {
    // opportunistic migration to bcrypt
    try {
      const newHash = await hashPassword(password);
      await dbRun("UPDATE users SET password_hash = ? WHERE id = ?", [newHash, userId]);
    } catch (e) {
      console.warn("[security] failed to migrate password hash for user", userId, e.message);
    }
  }
  return ok;
}

async function getAdminUser() {
  return dbGet("SELECT id, username, password_hash FROM users WHERE is_admin = 1 LIMIT 1");
}

// Ensure there's a concrete user row for the admin backed by the database (hashed credentials)
async function ensureAdminUser() {
  const existing = await getAdminUser();
  if (existing) return existing;

  const fallbackUsername = "@admin";
  const normalizedUsername = fallbackUsername;

  // Generate a strong temporary password; admin should rotate it immediately
  let adminPassword = crypto.randomBytes(12).toString("base64").replace(/[^a-zA-Z0-9]/g, "").slice(0, 16);
  if (process.env.NODE_ENV !== "production") {
    console.warn("[admin] Generated temporary admin password:", adminPassword);
  } else {
    console.warn("[admin] Generated temporary admin password; rotate immediately (value hidden in production logs)");
  }

  const email = "admin@example.local";
  const passwordHash = await hashPassword(adminPassword);

  const created = await dbRun(
    "INSERT OR IGNORE INTO users (username, email, password_hash, is_admin, full_name) VALUES (?, ?, ?, 1, ?)",
    [normalizedUsername, email, passwordHash, "Site Admin"]
  );

  const admin = await getAdminUser();
  if (admin) return admin;

  // If somehow still missing (e.g., username/email conflict), surface a clear error
  throw new Error("Failed to ensure admin user exists. Resolve username/email conflicts and retry.");
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  return res.status(403).json({ error: "Admin only" });
}

function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.status(401).json({ error: "Authentication required" });
}

function requireUserOnly(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: "Authentication required" });
  }
  if (req.session.isAdmin) {
    return res.status(403).json({ error: "Not available for admin" });
  }
  return next();
}

// Simple in-memory rate limiter (per IP)
function createRateLimiter({ limit, windowMs }) {
  const buckets = new Map();
  return (req, res, next) => 
  {
    const now = Date.now();
    const key = req.ip || "global";
    const entry = buckets.get(key) || [];
    const fresh = entry.filter((ts) => now - ts < windowMs);
    fresh.push(now);
    buckets.set(key, fresh);
    if (fresh.length > limit) {
      return res.status(429).json({ error: "Too many requests. Please slow down." });
    }
    next();
  };
}

const authLimiter = createRateLimiter({ limit: 10, windowMs: 5 * 60 * 1000 });
const writeLimiter = createRateLimiter({ limit: 200, windowMs: 5 * 60 * 1000 });

// CSRF guard for state-changing requests
const CSRF_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
function csrfGuard(req, res, next) {
  if (!CSRF_METHODS.has(req.method)) return next();
  const token = req.headers["x-csrf-token"];
  if (token && req.session && token === req.session.csrfToken) return next();
  return res.status(403).json({ error: "CSRF token invalid or missing" });
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

async function createNotification({ userId, postId, type, message, allowAdmin = false }) {
  try {
    if (!userId || !postId || !type || !message) return null;
    const user = await dbGet("SELECT id, is_admin FROM users WHERE id = ?", [userId]);
    if (!user) return null;
    if (user.is_admin && !allowAdmin) return null;
    const result = await dbRun(
      "INSERT INTO notifications (user_id, post_id, type, message) VALUES (?, ?, ?, ?)",
      [userId, postId, type, message]
    );
    return result.lastID;
  } catch (err) {
    console.error("notification error", err.message);
    return null;
  }
}

function extractMentions(text = "") {
  const mentions = new Set();
  const regex = /@([a-zA-Z0-9._-]{3,32})/g;
  let match;
  while ((match = regex.exec(text)) !== null) {
    mentions.add(match[1].toLowerCase());
  }
  return Array.from(mentions);
}

async function resolveUsernames(usernames = []) {
  if (!usernames.length) return [];
  const placeholders = usernames.map(() => "?").join(",");
  const rows = await dbAll(
    `SELECT id, username, is_admin FROM users WHERE lower(username) IN (${placeholders})`,
    usernames
  );
  return rows || [];
}

async function notifyMentions({ actorId, actorUsername, text, postId }) {
  if (!text || !postId) return;
  const usernames = extractMentions(text);
  if (!usernames.length) return;
  const targets = await resolveUsernames(usernames);
  for (const target of targets) {
    if (actorId && target.id === actorId) continue; // skip self-mention
    const label = actorUsername ? `@${actorUsername}` : "Someone";
    const message = `${label} mentioned you.`;
    await createNotification({
      userId: target.id,
      postId,
      type: "mention",
      message,
      allowAdmin: true,
    });
  }
}

// --------------------
// API routes
// --------------------

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime(), now: new Date().toISOString() });
});

// --------- ADMIN UTILITIES ---------
app.get("/api/admin/users/count", requireAdmin, async (req, res, next) => {
  try {
    const row = await dbGet("SELECT COUNT(*) as count FROM users WHERE is_admin = 0", []);
    res.json({ count: row ? row.count : 0 });
  } catch (err) {
    next(err);
  }
});

app.get("/api/admin/users", requireAdmin, async (req, res, next) => {
  try {
    const search = (req.query.search || "").toString().trim().toLowerCase();
    const params = [];
    let where = "WHERE is_admin = 0";
    if (search) {
      where += " AND lower(username) LIKE ?";
      params.push(`%${search}%`);
    }
    const rows = await dbAll(
      `SELECT id, username, full_name, email, avatar, bio, created_at
       FROM users
       ${where}
       ORDER BY lower(username) ASC`,
      params
    );
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// User Registration
app.post("/api/auth/register", authLimiter, async (req, res, next) => {
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
    const passwordHash = await hashPassword(password);
    const avatar = defaultAvatar();
    const result = await dbRun("INSERT INTO users (username, email, password_hash, full_name, avatar) VALUES (?, ?, ?, ?, ?)", 
      [username, email, passwordHash, fullName, avatar]);

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
app.post("/api/auth/login", authLimiter, async (req, res, next) => {
  try {
    const username = (req.body.username || "").toString().trim().toLowerCase();
    const password = (req.body.password || "").toString();

    if (!username || !password) return res.status(400).json({ error: "Username and password required" });

    const user = await dbGet("SELECT id, username, password_hash FROM users WHERE username = ?", [username]);
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const valid = await verifyPassword(password, user.password_hash, user.id);
    if (!valid) return res.status(401).json({ error: "Invalid credentials" });

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

// Admin Login (DB-backed, hashed)
app.post("/api/admin/login", authLimiter, async (req, res, next) => {
  try {
    const username = (req.body.username || "").toString().trim().toLowerCase();
    const password = (req.body.password || "").toString();

    if (!username || !password) return res.status(400).json({ error: "username and password required" });

    const adminUser = await ensureAdminUser();
    if (!adminUser) return res.status(500).json({ error: "Admin user is not initialized" });

    if (adminUser.username !== username) {
      return res.status(401).json({ ok: false, error: "Invalid credentials" });
    }

    const valid = await verifyPassword(password, adminUser.password_hash, adminUser.id);
    if (!valid) {
      return res.status(401).json({ ok: false, error: "Invalid credentials" });
    }

    req.session.isAdmin = true;
    req.session.userRole = "admin";
    req.session.userId = adminUser.id; // so admin actions needing user_id work
    req.session.username = adminUser.username;

    // Save session before responding to preserve login
    req.session.save((err) => {
      if (err) return res.status(500).json({ error: "Failed to create session" });
      res.json({ ok: true, userId: adminUser.id, username: adminUser.username });
    });
  } catch (err) {
    next(err);
  }
});

// Admin profile (fetch minimal data)
app.get("/api/admin/profile", requireAdmin, async (req, res, next) => {
  try {
    const admin = await getAdminUser();
    if (!admin) return res.status(404).json({ error: "Admin user not found" });
    res.json({ id: admin.id, username: admin.username });
  } catch (err) {
    next(err);
  }
});

// Update admin credentials (requires current password)
app.put("/api/admin/credentials", requireAdmin, async (req, res, next) => {
  try {
    const currentPassword = (req.body.currentPassword || "").toString();
    const newUsernameRaw = (req.body.newUsername || "").toString().trim();
    const newPassword = (req.body.newPassword || "").toString();

    if (!currentPassword) return res.status(400).json({ error: "Current password is required" });

    const admin = await getAdminUser();
    if (!admin) return res.status(404).json({ error: "Admin user not found" });

    const valid = await verifyPassword(currentPassword, admin.password_hash, admin.id);
    if (!valid) {
      return res.status(401).json({ error: "Current password is incorrect" });
    }

    const updates = [];
    const params = [];

    if (newUsernameRaw && newUsernameRaw.toLowerCase() !== admin.username) {
      const newUsername = newUsernameRaw.toLowerCase();
      const existing = await dbGet("SELECT id FROM users WHERE username = ? AND id != ?", [newUsername, admin.id]);
      if (existing) return res.status(409).json({ error: "Username is already taken" });
      updates.push("username = ?");
      params.push(newUsername);
    }

    if (newPassword) {
      if (newPassword.length < 6) return res.status(400).json({ error: "New password must be at least 6 characters" });
      updates.push("password_hash = ?");
      params.push(await hashPassword(newPassword));
    }

    if (!updates.length) return res.status(400).json({ error: "Nothing to update" });

    params.push(admin.id);
    await dbRun(`UPDATE users SET ${updates.join(", ")} WHERE id = ?`, params);

    const updated = await getAdminUser();
    req.session.username = updated.username;
    req.session.userId = updated.id;
    req.session.isAdmin = true;
    req.session.userRole = "admin";

    req.session.save((err) => {
      if (err) return res.status(500).json({ error: "Failed to refresh session" });
      res.json({ ok: true, username: updated.username });
    });
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

// CSRF token fetch
app.get("/api/auth/csrf", (req, res) => {
  res.json({ token: req.session.csrfToken });
});

// Get current user (replaces /api/me)
app.get("/api/auth/me", async (req, res, next) => {
  try {
    if (req.session.isAdmin) {
      const admin = await getAdminUser();
      return res.json({
        isAdmin: true,
        userRole: "admin",
        userId: (admin && admin.id) || req.session.userId || null,
        username: (admin && admin.username) || req.session.username || "@admin",
        avatar: "", // Admin deliberately has no avatar
      });
    }
    if (req.session.userId) {
      const user = await dbGet("SELECT id, username, full_name, email, bio, avatar FROM users WHERE id = ?", [req.session.userId]);
      return res.json({ id: user.id, userId: user.id, username: user.username, full_name: user.full_name, fullName: user.full_name, email: user.email, bio: user.bio, avatar: user.avatar || "", userRole: "user", isAdmin: false });
    }
    res.json({ isAdmin: false, userId: null, userRole: null });
  } catch (err) {
    next(err);
  }
});

// Username suggestions for mentions (must be authed to avoid harvesting)
app.get("/api/users/mention-suggest", requireAuth, async (req, res, next) => {
  try {
    const q = (req.query.q || "").toString().trim().toLowerCase();
    if (!q || q.length < 2) return res.json([]);

    const rows = await dbAll(
      `SELECT id, username, avatar, is_admin
         FROM users
         WHERE lower(username) LIKE ?
         ORDER BY is_admin DESC, lower(username) ASC
         LIMIT 6`,
      [`%${q}%`]
    );

    res.json(rows.map((r) => ({
      id: r.id,
      username: r.username,
      avatar: r.avatar || "",
      is_admin: !!r.is_admin,
    })));
  } catch (err) {
    next(err);
  }
});

// Keep /api/me for backwards compatibility
app.get("/api/me", async (req, res, next) => {
  try {
    if (req.session.isAdmin) {
      const admin = await getAdminUser();
      return res.json({ isAdmin: true, userId: (admin && admin.id) || req.session.userId || null, username: (admin && admin.username) || req.session.username || "@admin", avatar: "" });
    }
    if (req.session.userId) {
      const user = await dbGet("SELECT id, username, full_name, avatar FROM users WHERE id = ?", [req.session.userId]);
      return res.json({ isAdmin: false, userId: user.id, username: user.username, avatar: user.avatar || "" });
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

    const user = await dbGet("SELECT id, username, email, full_name, bio, created_at, avatar, is_admin FROM users WHERE id = ?", [userId]);
    if (!user) return res.status(404).json({ error: "User not found" });

    if (user.is_admin) {
      return res.status(403).json({ error: "Admin profile is not viewable here" });
    }

    // Get user's posts
    const posts = await dbAll("SELECT id, title, body, created_at FROM posts WHERE author_id = ? ORDER BY created_at DESC", [userId]);

    // Get user's comments with post context
    const comments = await dbAll(
      `SELECT c.id, c.post_id, c.body, c.created_at, c.updated_at, p.title as post_title
       FROM comments c
       JOIN posts p ON p.id = c.post_id
       WHERE c.user_id = ?
       ORDER BY c.created_at DESC`,
      [userId]
    );

    res.json({ id: user.id, username: user.username, email: user.email, full_name: user.full_name, bio: user.bio, avatar: user.avatar || "", created_at: user.created_at, posts, comments });
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
    const avatar = safeAvatar((req.body.avatar || "").toString());

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

    if (avatar) {
      updateFields.push("avatar = ?");
      updateParams.push(avatar);
    }

    if (updateFields.length > 0) {
      updateParams.push(req.session.userId);
      const updateSQL = `UPDATE users SET ${updateFields.join(", ")} WHERE id = ?`;
      await dbRun(updateSQL, updateParams);
    }

    const user = await dbGet("SELECT id, username, full_name, email, bio, avatar FROM users WHERE id = ?", [req.session.userId]);

    res.json({ id: user.id, username: user.username, full_name: user.full_name, email: user.email, bio: user.bio, avatar: user.avatar || "" });
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
        COALESCE(u.avatar, '') as author_avatar,
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
        COALESCE(u.avatar, '') as author_avatar,
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
        CASE WHEN p.author_id IS NULL THEN '@admin' ELSE u.username END as author_name,
        COALESCE(u.avatar, '') as author_avatar
      FROM posts p
      LEFT JOIN users u ON p.author_id = u.id
      WHERE p.id = ?
    `, [id]);
    const actorUsername = req.session.username || (req.session.isAdmin ? "admin" : "someone");
    await notifyMentions({ actorId: req.session.userId || null, actorUsername, text: `${title}\n${body}`, postId: id });

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

    if (req.session.isAdmin) {
      console.info(`[audit] admin ${req.session.username || '@admin'} deleted post ${id}`);
    }

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
    const post = await dbGet("SELECT id, author_id FROM posts WHERE id = ?", [id]);
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

    if (req.session.isAdmin) {
      console.info(`[audit] admin ${req.session.username || '@admin'} ${flagged ? 'flagged' : 'unflagged'} post ${id}`);
    }

    if (post.author_id) {
      const msg = flagged ? "Admin has flagged your post." : "Admin removed flag from your post.";
      await createNotification({ userId: post.author_id, postId: id, type: flagged ? "flagged" : "flag_removed", message: msg });
    }

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
        COALESCE(u.avatar, '') as author_avatar,
        CASE WHEN p.author_id IS NULL THEN 1 ELSE 0 END as is_admin_post
      FROM posts p LEFT JOIN users u ON p.author_id = u.id WHERE p.id = ?
    `, [result.lastID]);

    const actorUsername = req.session.username || (req.session.isAdmin ? "admin" : "someone");
    await notifyMentions({ actorId: req.session.userId || null, actorUsername, text: `${title}\n${body}`, postId: result.lastID });

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
      SELECT c.id, c.post_id, c.user_id, c.body, c.created_at, c.updated_at, u.username, COALESCE(u.avatar, '') as avatar, COALESCE(u.is_admin, 0) as is_admin
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
    const post = await dbGet("SELECT id, author_id FROM posts WHERE id = ?", [postId]);
    if (!post) return res.status(404).json({ error: "Post not found" });

    const result = await dbRun(
      "INSERT INTO comments (post_id, user_id, body) VALUES (?, ?, ?)",
      [postId, req.session.userId, body]
    );

    const comment = await dbGet(`
      SELECT c.id, c.post_id, c.user_id, c.body, c.created_at, c.updated_at, u.username
      , COALESCE(u.avatar, '') as avatar, COALESCE(u.is_admin, 0) as is_admin
      FROM comments c
      JOIN users u ON c.user_id = u.id
      WHERE c.id = ?
    `, [result.lastID]);

    if (post.author_id && post.author_id !== req.session.userId) {
      const actor = (comment && comment.username) ? comment.username : "Someone";
      await createNotification({
        userId: post.author_id,
        postId: postId,
        type: "comment",
        message: `${actor} commented on your post.`
      });
    }

    const actorUsername = (comment && comment.username) || req.session.username || "someone";
    await notifyMentions({ actorId: req.session.userId || null, actorUsername, text: body, postId });

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

    const actorUsername = (updated && updated.username) || req.session.username || "someone";
    await notifyMentions({ actorId: req.session.userId || null, actorUsername, text: body, postId: updated ? updated.post_id : undefined });

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
    const post = await dbGet("SELECT id, author_id FROM posts WHERE id = ?", [postId]);
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

    if (post.author_id && post.author_id !== req.session.userId) {
      const actor = req.session.username || "Someone";
      const reactionLabel = reactionType === 'useful' ? 'a 👍 reaction' : 'a 👎 reaction';
      await createNotification({
        userId: post.author_id,
        postId,
        type: "reaction",
        message: `${actor} left ${reactionLabel} on your post.`
      });
    }

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

// --------- NOTIFICATIONS (user only) ---------
app.get('/api/notifications', requireUserOnly, async (req, res, next) => {
  try {
    const rows = await dbAll(`
      SELECT n.id, n.post_id, n.type, n.message, n.is_read, n.created_at, COALESCE(p.title, '') as post_title
      FROM notifications n
      LEFT JOIN posts p ON n.post_id = p.id
      WHERE n.user_id = ?
      ORDER BY datetime(n.created_at) DESC
      LIMIT 100
    `, [req.session.userId]);
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

app.patch('/api/notifications/:id/read', requireUserOnly, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid notification id" });
    const result = await dbRun("UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?", [id, req.session.userId]);
    if (!result.changes) return res.status(404).json({ error: "Notification not found" });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

app.delete('/api/notifications/:id', requireUserOnly, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: "Invalid notification id" });
    const result = await dbRun("DELETE FROM notifications WHERE id = ? AND user_id = ?", [id, req.session.userId]);
    if (!result.changes) return res.status(404).json({ error: "Notification not found" });
    res.json({ ok: true });
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
          COALESCE(u.avatar, '') as author_avatar,
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
          COALESCE(u.avatar, '') as author_avatar,
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
