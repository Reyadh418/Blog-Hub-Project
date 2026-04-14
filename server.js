// Load environment variables
require("dotenv").config();

const express = require("express");
const path = require("path");
const session = require("express-session");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const db = require("./db");
const { sendVerificationCode } = require("./email");

// Note: PostgreSQL schema is initialized in db.js with correct defaults
// No additional migrations needed on startup

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

// Serve frontend files from /public with safe cache policy
app.use(express.static(path.join(__dirname, "public"), {
  etag: true,
  lastModified: true,
  maxAge: "1h",
  setHeaders: (res, filePath) => {
    if (filePath.endsWith("page-transitions.js")) {
      res.setHeader("Cache-Control", "no-cache");
      return;
    }
    if (filePath.endsWith(".html")) {
      res.setHeader("Cache-Control", "no-cache");
      return;
    }
    if (filePath.endsWith(".css") || filePath.endsWith(".js")) {
      res.setHeader("Cache-Control", "public, max-age=3600, stale-while-revalidate=300");
      return;
    }
    res.setHeader("Cache-Control", "public, max-age=600");
  },
}));

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

const REQUIRE_EMAIL_VERIFICATION = (process.env.REQUIRE_EMAIL_VERIFICATION || "0").toString() === "1";
const MAX_POST_WORDS = 5000;
const MAX_BIO_CHARS = 111;
const MAX_COMMENT_WORDS = 500;

function countWords(text) {
  const normalized = (text || "").toString().trim();
  if (!normalized) return 0;
  return normalized.split(/\s+/).filter(Boolean).length;
}

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
  return dbGet("SELECT id, username, password_hash, is_super_admin, is_promoted_admin FROM users WHERE is_admin = 1 ORDER BY is_super_admin DESC LIMIT 1");
}

// Get the super admin (THE one protected admin - there can only be one)
async function getSuperAdminId() {
  const superAdmin = await dbGet("SELECT id FROM users WHERE is_super_admin = 1 LIMIT 1");
  return superAdmin ? superAdmin.id : null;
}

// Check if user is the super admin
async function isSuperAdmin(userId) {
  const user = await dbGet("SELECT is_super_admin FROM users WHERE id = ?", [userId]);
  return user && Number(user.is_super_admin) === 1;
}

// Ensure there's a concrete user row for the admin backed by the database (hashed credentials)
async function ensureAdminUser() {
  console.log("[ensureAdminUser] Starting admin bootstrap...");
  const resetOnBoot = (process.env.ADMIN_RESET_ON_BOOT || "0").toString() === "1";
  const resetPassword = (process.env.ADMIN_PASSWORD || "").toString();
  const resetUsername = (process.env.ADMIN_USERNAME || "admin").toString().trim().toLowerCase();
  const resetEmail = (process.env.ADMIN_EMAIL || "").toString().trim().toLowerCase();
  console.log("[ensureAdminUser] Env: username=%s, passwordLen=%d, resetOnBoot=%s", resetUsername, resetPassword.length, resetOnBoot);

  // Check if a super admin already exists
  const superAdmin = await dbGet("SELECT id, username, password_hash, is_super_admin, is_promoted_admin FROM users WHERE is_super_admin = 1 LIMIT 1");
  console.log("[ensureAdminUser] Existing super admin:", superAdmin ? superAdmin.username : "NONE");
  if (superAdmin) {
    if (resetOnBoot && resetPassword.length >= 8) {
      const newHash = await hashPassword(resetPassword);
      const updateFields = ["password_hash = ?"];
      const updateParams = [newHash];

      if (resetUsername) {
        updateFields.push("username = ?");
        updateParams.push(resetUsername);
      }
      if (resetEmail) {
        updateFields.push("email = ?");
        updateParams.push(resetEmail);
      }

      updateParams.push(superAdmin.id);
      await dbRun(`UPDATE users SET ${updateFields.join(", ")} WHERE id = ?`, updateParams);
      console.warn("[admin] Super admin credentials were reset from env on boot. Turn off ADMIN_RESET_ON_BOOT after successful login.");
      const refreshed = await dbGet("SELECT id, username, password_hash, is_super_admin, is_promoted_admin FROM users WHERE id = ?", [superAdmin.id]);
      if (refreshed) return refreshed;
    }
    return superAdmin;
  }

  // Check if there's an admin user named 'admin' to promote
  const adminByName = await dbGet("SELECT id, username, password_hash, is_super_admin, is_promoted_admin FROM users WHERE is_admin = 1 AND username = 'admin' LIMIT 1");
  if (adminByName) {
    await dbRun("UPDATE users SET is_super_admin = 1, is_promoted_admin = 0 WHERE id = ?", [adminByName.id]);
    adminByName.is_super_admin = 1;
    return adminByName;
  }

  // No super admin exists. If any admin exists, promote the env/legacy admin username when present.
  const anyAdmin = await getAdminUser();
  console.log("[ensureAdminUser] Any admin found:", anyAdmin ? anyAdmin.username : "NONE");
  if (anyAdmin) {
    const targetUsername = resetUsername || "admin";
    const targetAdmin = await dbGet(
      "SELECT id, username, password_hash, is_super_admin, is_promoted_admin FROM users WHERE is_admin = 1 AND username = ? LIMIT 1",
      [targetUsername]
    );

    if (targetAdmin) {
      const updates = ["is_super_admin = 1", "is_promoted_admin = 0"];
      const updateParams = [];

      if (resetPassword.length >= 8) {
        const targetHash = await hashPassword(resetPassword);
        updates.push("password_hash = ?");
        updateParams.push(targetHash);
      }
      if (resetEmail) {
        updates.push("email = ?");
        updateParams.push(resetEmail);
      }

      updateParams.push(targetAdmin.id);
      await dbRun(`UPDATE users SET ${updates.join(", ")} WHERE id = ?`, updateParams);

      const refreshed = await dbGet("SELECT id, username, password_hash, is_super_admin, is_promoted_admin FROM users WHERE id = ?", [targetAdmin.id]);
      if (refreshed) return refreshed;
    }

    // Target admin username doesn't exist yet — fall through to create it below
    console.log("[ensureAdminUser] Target admin '%s' not found among existing admins, will create it", targetUsername);
  }

  // Seed from env when provided (recommended for production)
  const envAdminUsername = (process.env.ADMIN_USERNAME || "admin").toString().trim().toLowerCase();
  const envAdminPassword = (process.env.ADMIN_PASSWORD || "").toString();
  const email = (process.env.ADMIN_EMAIL || "admin@example.local").toString().trim().toLowerCase();

  let adminPassword = envAdminPassword;
  if (!adminPassword || adminPassword.length < 8) {
    adminPassword = crypto.randomBytes(12).toString("base64").replace(/[^a-zA-Z0-9]/g, "").slice(0, 16);
    if (process.env.NODE_ENV !== "production") {
      console.warn("[admin] Generated temporary admin password:", adminPassword);
    } else {
      console.warn("[admin] Generated temporary admin password; set ADMIN_PASSWORD and rotate immediately (value hidden in production logs)");
    }
  } else {
    if (process.env.NODE_ENV !== "production") {
      console.warn("[admin] Using ADMIN_PASSWORD from env; rotate regularly.");
    } else {
      console.warn("[admin] Using ADMIN_PASSWORD from env (value hidden); rotate regularly.");
    }
  }

  const normalizedUsername = envAdminUsername || "admin";
  const passwordHash = await hashPassword(adminPassword);

  console.log("[ensureAdminUser] Creating admin user: username=%s, email=%s", normalizedUsername, email);
  
  try {
    const created = await dbRun(
      "INSERT INTO users (username, email, password_hash, is_admin, is_super_admin, is_promoted_admin, full_name) VALUES (?, ?, ?, 1, 1, 0, ?) RETURNING id",
      [normalizedUsername, email, passwordHash, "Site Admin"]
    );
    console.log("[ensureAdminUser] INSERT result: lastID=%s, changes=%s", created.lastID, created.changes);
  } catch (insertErr) {
    console.error("[ensureAdminUser] INSERT failed:", insertErr.message);
    // If insert failed due to conflict, try updating instead
    console.log("[ensureAdminUser] Attempting UPDATE fallback...");
    await dbRun(
      "UPDATE users SET password_hash = ?, email = ?, is_admin = 1, is_super_admin = 1, is_promoted_admin = 0, full_name = ? WHERE username = ?",
      [passwordHash, email, "Site Admin", normalizedUsername]
    );
    console.log("[ensureAdminUser] UPDATE fallback completed");
  }

  const admin = await getAdminUser();
  console.log("[ensureAdminUser] Final admin check:", admin ? admin.username : "STILL NONE");
  if (admin) return admin;

  // If somehow still missing (e.g., username/email conflict), surface a clear error
  throw new Error("Failed to ensure admin user exists. Resolve username/email conflicts and retry.");
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  return res.status(403).json({ error: "Admin only" });
}

async function requireSuperAdmin(req, res, next) {
  if (!req.session || !req.session.isAdmin) {
    return res.status(403).json({ error: "Super Admin only" });
  }
  
  // If session has isSuperAdmin flag, use it
  if (req.session.isSuperAdmin === true) return next();
  
  // Otherwise check the database (for sessions created before this feature)
  try {
    const user = await dbGet("SELECT is_super_admin FROM users WHERE id = ? AND is_admin = 1", [req.session.userId]);
    if (user && Number(user.is_super_admin) === 1) {
      // Update session for future requests
      req.session.isSuperAdmin = true;
      return next();
    }
  } catch (err) {
    console.error("requireSuperAdmin check failed", err);
  }
  
  return res.status(403).json({ error: "Super Admin only" });
}

function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.status(401).json({ error: "Authentication required" });
}

function requireUserOnly(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: "Authentication required" });
  }
  if (req.session.isSuperAdmin) {
    return res.status(403).json({ error: "Not available for Super Admin" });
  }
  return next();
}

// Require verified email for selected write operations (admins exempt)
async function requireVerified(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: "Authentication required" });
  }

  if (!REQUIRE_EMAIL_VERIFICATION) return next();
  if (req.session.isAdmin) return next();
  if (req.session.emailVerified === true) return next();

  try {
    const user = await dbGet("SELECT email_verified FROM users WHERE id = ?", [req.session.userId]);
    const emailVerified = user && Number(user.email_verified) === 1;
    req.session.emailVerified = emailVerified;

    if (!emailVerified) {
      return res.status(403).json({ error: "Email verification required", code: "EMAIL_NOT_VERIFIED" });
    }

    return next();
  } catch (err) {
    return next(err);
  }
}

// Generate a random 6-digit verification code
function generateVerificationCode() {
  return crypto.randomInt(100000, 999999).toString();
}

// Hash a verification code for secure storage
function hashVerificationCode(code) {
  return crypto.createHash("sha256").update(code).digest("hex");
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

// Helper to convert SQLite ? placeholders to PostgreSQL $1, $2 syntax
function convertPlaceholders(sql, params = []) {
  let paramIndex = 1;
  const converted = sql.replace(/\?/g, () => `$${paramIndex++}`);
  return { sql: converted, params };
}

const dbRun = async (sql, params = []) => {
  const { sql: convertedSql, params: convertedParams } = convertPlaceholders(sql, params);
  const result = await db.run(convertedSql, convertedParams);
  return result;
};

const dbGet = async (sql, params = []) => {
  const { sql: convertedSql, params: convertedParams } = convertPlaceholders(sql, params);
  const row = await db.get(convertedSql, convertedParams);
  return row || null;
};

const CATEGORY_TAXONOMY = Object.freeze(["Education", "Stories", "Mindset", "Lessons"]);
const CATEGORY_ALIASES = Object.freeze({
  education: "Education",
  stories: "Stories",
  story: "Stories",
  mindset: "Mindset",
  lessons: "Lessons",
  lesson: "Lessons",
  "life lessons": "Lessons",
  discipline: "Mindset",
  "real stories": "Stories",
  career: "Education",
});

function canonicalizeCategory(value) {
  const key = (value || "").toString().trim().toLowerCase();
  if (!key) return null;
  return CATEGORY_ALIASES[key] || null;
}

function parseTagsArray(rawTags) {
  if (Array.isArray(rawTags)) return rawTags;
  if (rawTags == null) return [];
  if (typeof rawTags === "string") {
    try {
      const parsed = JSON.parse(rawTags);
      if (Array.isArray(parsed)) return parsed;
    } catch {
      return rawTags
        .toString()
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    }
  }
  return rawTags
    .toString()
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function normalizePostTags(rawTags, preferredCategory = null) {
  const parsed = parseTagsArray(rawTags)
    .map((s) => (s || "").toString().trim())
    .filter(Boolean);

  const unique = [];
  const seen = new Set();
  parsed.forEach((token) => {
    const lower = token.toLowerCase();
    if (seen.has(lower)) return;
    seen.add(lower);
    unique.push(token);
  });

  const inferredCategory =
    canonicalizeCategory(preferredCategory) || unique.map((token) => canonicalizeCategory(token)).find(Boolean) || "Stories";

  const filtered = unique.filter((token) => !canonicalizeCategory(token));
  return [inferredCategory, ...filtered];
}

function extractCategoryFromTags(tags) {
  return normalizePostTags(tags).find((token) => CATEGORY_TAXONOMY.includes(token)) || "Stories";
}

function normalizePostRow(row) {
  if (!row || typeof row !== "object") return row;
  const tags = normalizePostTags(row.tags, row.category || null);
  return {
    ...row,
    tags,
    category: extractCategoryFromTags(tags),
  };
}

const dbAll = async (sql, params = []) => {
  const { sql: convertedSql, params: convertedParams } = convertPlaceholders(sql, params);
  const rows = await db.all(convertedSql, convertedParams);
  const normalized = rows.map((r) => normalizePostRow(r));
  return normalized;
};

async function createNotification({ userId, postId, type, message, allowAdmin = false }) {
  try {
    if (!userId || !postId || !type || !message) return null;
    const user = await dbGet("SELECT id, is_admin, is_super_admin FROM users WHERE id = ?", [userId]);
    if (!user) return null;
    const result = await dbRun(
      "INSERT INTO notifications (user_id, post_id, type, message) VALUES (?, ?, ?, ?) RETURNING id",
      [userId, postId, type, message]
    );
    return result.lastID;
  } catch (err) {
    console.error("notification error", err.message);
    return null;
  }
}

async function logAdminAudit({ actorAdminId, targetUserId = null, actionType, details = "" }) {
  try {
    if (!actorAdminId || !actionType) return;
    await dbRun(
      "INSERT INTO admin_audit_logs (actor_admin_id, target_user_id, action_type, details) VALUES (?, ?, ?, ?)",
      [actorAdminId, targetUserId, actionType, (details || "").toString().slice(0, 800)]
    );
  } catch (err) {
    console.error("admin audit log failed", err.message);
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
    const row = await dbGet("SELECT COUNT(*) as count FROM users", []);
    res.json({ count: row ? row.count : 0 });
  } catch (err) {
    next(err);
  }
});

app.get("/api/admin/users", requireAdmin, async (req, res, next) => {
  try {
    const search = (req.query.search || "").toString().trim().toLowerCase();
    const params = [];
    let where = "WHERE 1=1";
    if (search) {
      where += " AND lower(u.username) LIKE ?";
      params.push(`%${search}%`);
    }
    const rows = await dbAll(
      `SELECT u.id, u.username, u.full_name, u.email, u.avatar, u.bio, u.created_at,
              u.email_verified, u.is_author_verified, u.author_verified_by_admin_id, u.author_verified_at,
              u.is_admin, u.is_super_admin, u.is_promoted_admin,
              verifier.username as author_verified_by_admin_username
       FROM users u
       LEFT JOIN users verifier ON verifier.id = u.author_verified_by_admin_id
       ${where}
       ORDER BY u.is_admin DESC, lower(u.username) ASC`,
      params
    );
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

app.get("/api/admin/authors", requireAdmin, async (req, res, next) => {
  try {
    const search = (req.query.search || "").toString().trim().toLowerCase();
    const params = [];
    let where = "WHERE u.is_admin = 0";
    if (search) {
      where += " AND (lower(u.username) LIKE ? OR lower(u.email) LIKE ? OR lower(COALESCE(u.full_name, '')) LIKE ?)";
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }

    const rows = await dbAll(
      `SELECT u.id, u.username, u.full_name, u.email, u.avatar, u.created_at,
              u.email_verified, u.is_author_verified, u.author_verified_by_admin_id, u.author_verified_at,
              verifier.username AS author_verified_by_admin_username
       FROM users u
       LEFT JOIN users verifier ON verifier.id = u.author_verified_by_admin_id
       ${where}
       ORDER BY u.is_author_verified DESC, u.email_verified DESC, lower(u.username) ASC
       LIMIT 60`,
      params
    );

    res.json(rows.map((row) => ({
      id: row.id,
      username: row.username,
      fullName: row.full_name || "",
      email: row.email,
      avatar: row.avatar || "",
      createdAt: row.created_at,
      emailVerified: Number(row.email_verified) === 1,
      authorVerified: Number(row.is_author_verified) === 1,
      verifiedByAdminId: row.author_verified_by_admin_id || null,
      verifiedByAdminUsername: row.author_verified_by_admin_username || null,
      verifiedAt: row.author_verified_at || null,
    })));
  } catch (err) {
    next(err);
  }
});

app.patch("/api/admin/authors/:id/verification", requireAdmin, async (req, res, next) => {
  try {
    const authorId = Number(req.params.id);
    if (!Number.isInteger(authorId) || authorId <= 0) {
      return res.status(400).json({ error: "Invalid author id" });
    }

    const target = await dbGet(
      `SELECT id, username, is_admin, email_verified, is_author_verified
       FROM users
       WHERE id = ?`,
      [authorId]
    );

    if (!target) return res.status(404).json({ error: "Author not found" });
    if (Number(target.is_admin) === 1) {
      return res.status(400).json({ error: "Admin accounts always use Admin trust label" });
    }

    const verified = req.body.verified === true;
    if (verified && Number(target.email_verified) !== 1) {
      return res.status(400).json({ error: "Cannot mark as verified until email is verified" });
    }

    if (verified) {
      await dbRun(
        `UPDATE users
         SET is_author_verified = 1,
             author_verified_by_admin_id = ?,
             author_verified_at = CURRENT_TIMESTAMP
         WHERE id = ?`,
        [req.session.userId, authorId]
      );

      await dbRun(
        "INSERT INTO notifications (user_id, post_id, type, message) VALUES (?, NULL, 'profile', ?)",
        [authorId, '✅ Your author profile was marked as Verified by an admin.']
      );

      await logAdminAudit({
        actorAdminId: req.session.userId,
        targetUserId: authorId,
        actionType: "author_verify",
        details: `Marked @${target.username} as Verified author`,
      });
    } else {
      await dbRun(
        `UPDATE users
         SET is_author_verified = 0,
             author_verified_by_admin_id = NULL,
             author_verified_at = NULL
         WHERE id = ?`,
        [authorId]
      );

      await logAdminAudit({
        actorAdminId: req.session.userId,
        targetUserId: authorId,
        actionType: "author_unverify",
        details: `Set @${target.username} author trust to Community`,
      });
    }

    const updated = await dbGet(
      `SELECT u.id, u.username, u.email_verified, u.is_author_verified, u.author_verified_at,
              u.author_verified_by_admin_id, verifier.username AS author_verified_by_admin_username
       FROM users u
       LEFT JOIN users verifier ON verifier.id = u.author_verified_by_admin_id
       WHERE u.id = ?`,
      [authorId]
    );

    res.json({
      ok: true,
      author: {
        id: updated.id,
        username: updated.username,
        emailVerified: Number(updated.email_verified) === 1,
        authorVerified: Number(updated.is_author_verified) === 1,
        verifiedAt: updated.author_verified_at || null,
        verifiedByAdminId: updated.author_verified_by_admin_id || null,
        verifiedByAdminUsername: updated.author_verified_by_admin_username || null,
      },
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/users/verification-request - User submits a verification request
app.post("/api/users/verification-request", requireAuth, async (req, res, next) => {
  try {
    const userId = req.session.userId;
    const reason = (req.body.reason || "").toString().trim().substring(0, 500);

    // Fetch current user to check eligibility
    const user = await dbGet(
      "SELECT id, username, email_verified, is_author_verified FROM users WHERE id = ?",
      [userId]
    );

    if (!user) return res.status(404).json({ error: "User not found" });
    if (Number(user.is_author_verified) === 1) {
      return res.status(400).json({ error: "You are already verified" });
    }
    if (Number(user.email_verified) !== 1) {
      return res.status(400).json({ error: "Email must be verified before requesting verification" });
    }

    // Check if user already has a pending request
    const existing = await dbGet(
      "SELECT id FROM verification_requests WHERE user_id = ? AND status = 'pending'",
      [userId]
    );

    if (existing) {
      return res.status(400).json({ error: "You already have a pending verification request" });
    }

    // Create verification request
    const result = await dbRun(
      "INSERT INTO verification_requests (user_id, reason, status) VALUES (?, ?, 'pending') RETURNING id",
      [userId, reason]
    );

    // Notify super-admins of new verification request
    const superAdmins = await dbAll(
      "SELECT id FROM users WHERE is_super_admin = 1"
    );

    for (const admin of superAdmins) {
      await dbRun(
        "INSERT INTO notifications (user_id, post_id, type, message) VALUES (?, NULL, 'verification_request', ?)",
        [admin.id, `📤 @${user.username} submitted a verification request`]
      );
    }

    res.status(201).json({
      ok: true,
      verificationRequest: {
        id: result.lastID,
        status: "pending",
        createdAt: new Date().toISOString(),
      },
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/admin/verification-requests - Get all verification requests for super-admin review
app.get("/api/admin/verification-requests", requireSuperAdmin, async (req, res, next) => {
  try {
    const status = req.query.status || "pending";
    
    const requests = await dbAll(
      `SELECT vr.id, vr.user_id, vr.status, vr.reason, vr.created_at, vr.reviewed_at,
              vr.reviewed_by_admin_id, vr.decision_message,
              u.username, u.avatar, u.full_name,
              reviewer.username AS reviewed_by_admin_username
       FROM verification_requests vr
       JOIN users u ON u.id = vr.user_id
       LEFT JOIN users reviewer ON reviewer.id = vr.reviewed_by_admin_id
       WHERE vr.status = ?
       ORDER BY vr.created_at DESC`,
      [status]
    );

    const formatted = requests.map(vr => ({
      id: vr.id,
      userId: vr.user_id,
      username: vr.username,
      avatar: vr.avatar || null,
      fullName: vr.full_name || null,
      status: vr.status,
      reason: vr.reason,
      createdAt: vr.created_at,
      reviewedAt: vr.reviewed_at || null,
      reviewedByAdminId: vr.reviewed_by_admin_id || null,
      reviewedByAdminUsername: vr.reviewed_by_admin_username || null,
      decisionMessage: vr.decision_message,
    }));

    res.json({ ok: true, verificationRequests: formatted });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/admin/verification-requests/:id/approve - Approve a verification request
app.patch("/api/admin/verification-requests/:id/approve", requireSuperAdmin, async (req, res, next) => {
  try {
    const requestId = Number(req.params.id);
    if (!Number.isInteger(requestId) || requestId <= 0) {
      return res.status(400).json({ error: "Invalid verification request id" });
    }

    const verificationRequest = await dbGet(
      "SELECT id, user_id, status FROM verification_requests WHERE id = ?",
      [requestId]
    );

    if (!verificationRequest) {
      return res.status(404).json({ error: "Verification request not found" });
    }

    if (verificationRequest.status !== "pending") {
      return res.status(400).json({ error: "Can only approve pending requests" });
    }

    const userId = verificationRequest.user_id;
    const user = await dbGet("SELECT username FROM users WHERE id = ?", [userId]);

    // Mark user as verified
    await dbRun(
      `UPDATE users
       SET is_author_verified = 1,
           author_verified_by_admin_id = ?,
           author_verified_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [req.session.userId, userId]
    );

    // Update verification request status
    await dbRun(
      `UPDATE verification_requests
       SET status = 'approved',
           reviewed_by_admin_id = ?,
           reviewed_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [req.session.userId, requestId]
    );

    // Notify user of approval
    await dbRun(
      "INSERT INTO notifications (user_id, post_id, type, message) VALUES (?, NULL, 'verification_complete', ?)",
      [userId, "✅ Your author verification was approved!"]
    );

    // Log audit
    await logAdminAudit({
      actorAdminId: req.session.userId,
      targetUserId: userId,
      actionType: "verification_request_approve",
      details: `Approved verification request for @${user.username}`,
    });

    res.json({
      ok: true,
      message: `@${user.username} is now verified`,
    });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/admin/verification-requests/:id/reject - Reject a verification request
app.patch("/api/admin/verification-requests/:id/reject", requireSuperAdmin, async (req, res, next) => {
  try {
    const requestId = Number(req.params.id);
    const decisionMessage = (req.body.message || "").toString().trim().substring(0, 300);

    if (!Number.isInteger(requestId) || requestId <= 0) {
      return res.status(400).json({ error: "Invalid verification request id" });
    }

    const verificationRequest = await dbGet(
      "SELECT id, user_id, status FROM verification_requests WHERE id = ?",
      [requestId]
    );

    if (!verificationRequest) {
      return res.status(404).json({ error: "Verification request not found" });
    }

    if (verificationRequest.status !== "pending") {
      return res.status(400).json({ error: "Can only reject pending requests" });
    }

    const userId = verificationRequest.user_id;
    const user = await dbGet("SELECT username FROM users WHERE id = ?", [userId]);

    // Update verification request status
    await dbRun(
      `UPDATE verification_requests
       SET status = 'rejected',
           reviewed_by_admin_id = ?,
           reviewed_at = CURRENT_TIMESTAMP,
           decision_message = ?
       WHERE id = ?`,
      [req.session.userId, decisionMessage, requestId]
    );

    // Notify user of rejection
    const message = decisionMessage
      ? `⚠️ Your verification request was rejected: "${decisionMessage}"`
      : "⚠️ Your verification request was rejected";
    
    await dbRun(
      "INSERT INTO notifications (user_id, post_id, type, message) VALUES (?, NULL, 'verification_rejected', ?)",
      [userId, message]
    );

    // Log audit
    await logAdminAudit({
      actorAdminId: req.session.userId,
      targetUserId: userId,
      actionType: "verification_request_reject",
      details: `Rejected verification request for @${user.username}${decisionMessage ? `: ${decisionMessage}` : ''}`,
    });

    res.json({
      ok: true,
      message: `Verification request for @${user.username} rejected`,
    });
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
    const result = await dbRun("INSERT INTO users (username, email, password_hash, full_name, avatar) VALUES (?, ?, ?, ?, ?) RETURNING id", 
      [username, email, passwordHash, fullName, avatar]);

    // Generate verification code
    const verificationCode = generateVerificationCode();
    const hashedCode = hashVerificationCode(verificationCode);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    await dbRun(
      "UPDATE users SET verification_code = ?, verification_code_expires = ? WHERE id = ?",
      [hashedCode, expiresAt, result.lastID]
    );

    // Send verification email (async, don't block response)
    sendVerificationCode(email, verificationCode, username).catch(err => {
      console.error("[email] Failed to send code on register:", err.message);
    });

    // Auto-login after registration (but unverified)
    req.session.userId = result.lastID;
    req.session.username = username;
    req.session.userRole = "user";
    req.session.emailVerified = false;

    // Save session before responding to preserve login
    req.session.save((err) => {
      if (err) return res.status(500).json({ error: "Failed to create session" });
      res.status(201).json({ ok: true, userId: result.lastID, username, emailVerified: false });
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

    // Unified login: fetch all user data including admin status
    const user = await dbGet(
      "SELECT id, username, password_hash, is_admin, is_super_admin, is_promoted_admin FROM users WHERE username = ?",
      [username]
    );
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const valid = await verifyPassword(password, user.password_hash, user.id);
    if (!valid) return res.status(401).json({ error: "Invalid credentials" });

    // Check email verification status from DB
    const fullUser = await dbGet("SELECT email_verified FROM users WHERE id = ?", [user.id]);
    const emailVerified = fullUser && Number(fullUser.email_verified) === 1;

    // Set unified session variables based on database values
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.isAdmin = Number(user.is_admin) === 1;
    req.session.isSuperAdmin = Number(user.is_super_admin) === 1;
    req.session.isPromotedAdmin = Number(user.is_promoted_admin) === 1;
    req.session.userRole = Number(user.is_admin) === 1 ? "admin" : "user";
    req.session.emailVerified = emailVerified;

    // Save session before responding to preserve login
    req.session.save((err) => {
      if (err) return res.status(500).json({ error: "Failed to create session" });
      res.json({ 
        ok: true, 
        userId: user.id, 
        username: user.username,
        isAdmin: Number(user.is_admin) === 1,
        isSuperAdmin: Number(user.is_super_admin) === 1,
        isPromotedAdmin: Number(user.is_promoted_admin) === 1,
        emailVerified
      });
    });
  } catch (err) {
    next(err);
  }
});

// Admin profile (fetch minimal data)
app.get("/api/admin/profile", requireAdmin, async (req, res, next) => {
  try {
    const admin = await dbGet("SELECT id, username, is_super_admin, is_promoted_admin FROM users WHERE id = ?", [req.session.userId]);
    if (!admin) return res.status(404).json({ error: "Admin user not found" });
    
    const adminCount = await dbGet("SELECT COUNT(*) as count FROM users WHERE is_admin = 1", []);
    
    res.json({
      id: admin.id,
      username: admin.username,
      isSuperAdmin: Number(admin.is_super_admin) === 1,
      isPromotedAdmin: Number(admin.is_promoted_admin) === 1,
      adminCount: adminCount ? adminCount.count : 0,
    });
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

    // Get the currently logged in admin, not just any admin
    const adminId = req.session.userId;
    if (!adminId) return res.status(401).json({ error: "Not authenticated" });
    
    const admin = await dbGet("SELECT id, username, password_hash, is_super_admin FROM users WHERE id = ? AND is_admin = 1", [adminId]);
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

    // Refresh session with the updated admin data
    const updated = await dbGet("SELECT id, username, is_super_admin FROM users WHERE id = ?", [admin.id]);
    req.session.username = updated.username;
    req.session.userId = updated.id;
    req.session.isAdmin = true;
    req.session.isSuperAdmin = Number(updated.is_super_admin) === 1;
    req.session.userRole = "admin";

    req.session.save((err) => {
      if (err) return res.status(500).json({ error: "Failed to refresh session" });
      res.json({ ok: true, username: updated.username });
    });
  } catch (err) {
    next(err);
  }
});

// =====================================================
// ADMIN MANAGEMENT ENDPOINTS (Super Admin only for most actions)
// =====================================================

// Get all admins
app.get("/api/admin/admins", requireAdmin, async (req, res, next) => {
  try {
    const admins = await dbAll(
      `SELECT id, username, email, full_name, avatar, is_super_admin, is_promoted_admin, created_at 
       FROM users WHERE is_admin = 1 ORDER BY is_super_admin DESC, created_at ASC`
    );
    res.json(admins.map(a => ({
      id: a.id,
      username: a.username,
      email: a.email,
      fullName: a.full_name || '',
      avatar: a.avatar || '',
      isSuperAdmin: Number(a.is_super_admin) === 1,
      isPromotedAdmin: Number(a.is_promoted_admin) === 1,
      createdAt: a.created_at
    })));
  } catch (err) {
    next(err);
  }
});

app.get("/api/admin/audit-trail", requireAdmin, async (req, res, next) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
    const actionType = (req.query.actionType || "").toString().trim().toLowerCase();
    const query = (req.query.q || "").toString().trim().toLowerCase();
    const rawWindowDays = Number(req.query.windowDays);
    const windowDays = Number.isFinite(rawWindowDays) && rawWindowDays > 0
      ? Math.min(Math.floor(rawWindowDays), 365)
      : 0;

    const allowedActionTypes = new Set([
      "author_verify",
      "author_unverify",
      "admin_promote",
      "admin_demote",
      "admin_step_down",
      "super_admin_transfer",
    ]);

    if (actionType && !allowedActionTypes.has(actionType)) {
      return res.status(400).json({ error: "Invalid action filter" });
    }

    const where = [];
    const params = [];

    if (actionType) {
      where.push("l.action_type = ?");
      params.push(actionType);
    }

    if (query) {
      where.push(`(
        LOWER(COALESCE(actor.username, '')) LIKE ?
        OR LOWER(COALESCE(target.username, '')) LIKE ?
        OR LOWER(COALESCE(l.details, '')) LIKE ?
      )`);
      const likeQuery = `%${query}%`;
      params.push(likeQuery, likeQuery, likeQuery);
    }

    if (windowDays > 0) {
      where.push("l.created_at >= datetime('now', ?)");
      params.push(`-${windowDays} days`);
    }

    const whereClause = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const rows = await dbAll(
      `SELECT l.id, l.actor_admin_id, l.target_user_id, l.action_type, l.details, l.created_at,
              actor.username AS actor_username,
              target.username AS target_username
       FROM admin_audit_logs l
       LEFT JOIN users actor ON actor.id = l.actor_admin_id
       LEFT JOIN users target ON target.id = l.target_user_id
       ${whereClause}
       ORDER BY l.created_at DESC
       LIMIT ?`,
      [...params, limit]
    );

    res.json(rows.map((r) => ({
      id: r.id,
      actorAdminId: r.actor_admin_id,
      actorUsername: r.actor_username || "unknown",
      targetUserId: r.target_user_id || null,
      targetUsername: r.target_username || null,
      actionType: r.action_type,
      details: r.details || "",
      createdAt: r.created_at,
    })));
  } catch (err) {
    next(err);
  }
});

// Search users (for promoting to admin)
app.get("/api/admin/users/search", requireSuperAdmin, async (req, res, next) => {
  try {
    const q = (req.query.q || "").toString().trim().toLowerCase();
    if (q.length < 2) return res.json([]);
    
    const users = await dbAll(
      `SELECT id, username, email, full_name, avatar, is_admin 
       FROM users 
       WHERE is_admin = 0 AND (LOWER(username) LIKE ? OR LOWER(email) LIKE ? OR LOWER(full_name) LIKE ?)
       LIMIT 20`,
      [`%${q}%`, `%${q}%`, `%${q}%`]
    );
    res.json(users.map(u => ({
      id: u.id,
      username: u.username,
      email: u.email,
      fullName: u.full_name || '',
      avatar: u.avatar || ''
    })));
  } catch (err) {
    next(err);
  }
});

// Promote user to admin (Super Admin only - promotes to Promoted Admin)
app.post("/api/admin/admins/promote", requireSuperAdmin, async (req, res, next) => {
  try {
    const userId = parseInt(req.body.userId, 10);
    
    if (!userId || isNaN(userId)) return res.status(400).json({ error: "userId is required" });
    
    // Check user exists and is not already an admin
    const user = await dbGet("SELECT id, username, is_admin FROM users WHERE id = ?", [userId]);
    if (!user) return res.status(404).json({ error: "User not found" });
    if (Number(user.is_admin) === 1) return res.status(400).json({ error: "User is already an admin" });
    
    // Promote to Promoted Admin (not Super Admin - there can only be ONE super admin)
    await dbRun(
      "UPDATE users SET is_admin = 1, is_super_admin = 0, is_promoted_admin = 1 WHERE id = ?",
      [userId]
    );
    
    // Send notification to the promoted user
    const notifMessage = '🎉 Congratulations! You have been promoted to Admin. You can now manage content on the site.';
    await dbRun(
      "INSERT INTO notifications (user_id, post_id, type, message) VALUES (?, NULL, 'promotion', ?)",
      [userId, notifMessage]
    );

    await logAdminAudit({
      actorAdminId: req.session.userId,
      targetUserId: userId,
      actionType: "admin_promote",
      details: `Promoted @${user.username} to Promoted Admin`,
    });
    
    res.json({ ok: true, message: `${user.username} is now a Promoted Admin` });
  } catch (err) {
    next(err);
  }
});

// Demote admin to regular user (Super Admin only)
app.post("/api/admin/admins/demote", requireSuperAdmin, async (req, res, next) => {
  try {
    const userId = parseInt(req.body.userId, 10);
    const currentUserId = req.session.userId;
    
    if (!userId || isNaN(userId)) return res.status(400).json({ error: "userId is required" });
    
    // Get target user
    const targetUser = await dbGet("SELECT id, username, is_admin, is_super_admin, is_promoted_admin FROM users WHERE id = ?", [userId]);
    if (!targetUser) return res.status(404).json({ error: "User not found" });
    if (targetUser.is_admin !== 1) return res.status(400).json({ error: "User is not an admin" });
    
    // RULE: Super Admin CANNOT be demoted by anyone (including themselves via this endpoint)
    if (targetUser.is_super_admin === 1) {
      return res.status(403).json({ error: "The Super Admin cannot be demoted. Use 'Transfer Super Admin' to pass the role to someone else." });
    }

    // RULE: Super Admin cannot demote themselves (they must transfer first)
    if (userId === currentUserId) {
      return res.status(400).json({ error: "Super Admin cannot demote themselves. Transfer Super Admin status first." });
    }
    
    // Perform demotion
    await dbRun(
      "UPDATE users SET is_admin = 0, is_super_admin = 0, is_promoted_admin = 0 WHERE id = ?",
      [userId]
    );
    
    // Send notification to the demoted user (if not self-demote)
    if (userId !== currentUserId) {
      await dbRun(
        "INSERT INTO notifications (user_id, post_id, type, message) VALUES (?, NULL, 'demotion', ?)",
        [userId, '📋 Your admin privileges have been removed. You are now a regular user.']
      );
    }

    await logAdminAudit({
      actorAdminId: currentUserId,
      targetUserId: userId,
      actionType: "admin_demote",
      details: `Demoted @${targetUser.username} to regular user`,
    });
    
    const message = `${targetUser.username} is no longer an admin`;
    
    res.json({ ok: true, message, selfDemote: false });
  } catch (err) {
    next(err);
  }
});

// Promoted admin self step-down endpoint
app.post("/api/admin/self/step-down", requireAdmin, async (req, res, next) => {
  try {
    const currentUserId = req.session.userId;
    const currentUser = await dbGet("SELECT id, username, is_super_admin, is_promoted_admin FROM users WHERE id = ?", [currentUserId]);
    if (!currentUser) return res.status(401).json({ error: "Not authenticated" });
    if (Number(currentUser.is_super_admin) === 1) {
      return res.status(403).json({ error: "Super Admin must transfer role instead of stepping down here" });
    }
    if (Number(currentUser.is_promoted_admin) !== 1) {
      return res.status(400).json({ error: "Only promoted admins can step down here" });
    }

    await dbRun(
      "UPDATE users SET is_admin = 0, is_super_admin = 0, is_promoted_admin = 0 WHERE id = ?",
      [currentUserId]
    );

    await logAdminAudit({
      actorAdminId: currentUserId,
      targetUserId: currentUserId,
      actionType: "admin_step_down",
      details: `@${currentUser.username} stepped down from Promoted Admin`,
    });

    req.session.isAdmin = false;
    req.session.isPromotedAdmin = false;
    req.session.isSuperAdmin = false;
    req.session.userRole = "user";

    res.json({ ok: true, message: "You have stepped down from admin role." });
  } catch (err) {
    next(err);
  }
});

// Transfer Super Admin status to another admin (Super Admin only)
// This is the ONLY way to change Super Admin - they choose their successor
app.post("/api/admin/admins/transfer-super", requireSuperAdmin, async (req, res, next) => {
  try {
    const newSuperAdminId = parseInt(req.body.userId, 10);
    const currentUserId = req.session.userId;
    const password = (req.body.password || "").toString();
    
    if (!newSuperAdminId || isNaN(newSuperAdminId)) {
      return res.status(400).json({ error: "userId is required" });
    }
    if (!password) {
      return res.status(400).json({ error: "Password is required to transfer Super Admin" });
    }
    
    // Cannot transfer to yourself
    if (newSuperAdminId === currentUserId) {
      return res.status(400).json({ error: "You are already the Super Admin" });
    }

    // Verify current super admin password
    const currentUser = await dbGet("SELECT id, username, password_hash FROM users WHERE id = ?", [currentUserId]);
    if (!currentUser) return res.status(401).json({ error: "Authentication required" });
    const validPassword = await verifyPassword(password, currentUser.password_hash, currentUser.id);
    if (!validPassword) {
      return res.status(401).json({ error: "Incorrect password. Transfer aborted." });
    }
    
    // Target must be an existing admin (promoted admin)
    const targetUser = await dbGet(
      "SELECT id, username, is_admin, is_promoted_admin FROM users WHERE id = ?", 
      [newSuperAdminId]
    );
    if (!targetUser) return res.status(404).json({ error: "User not found" });
    if (targetUser.is_admin !== 1) {
      return res.status(400).json({ error: "Target user must be an admin first. Promote them to admin first." });
    }
    
    // Transfer: Remove super admin from current, give to new (atomic transaction)
    await dbRun("BEGIN TRANSACTION");
    await dbRun(
      "UPDATE users SET is_super_admin = 0, is_promoted_admin = 1 WHERE id = ?",
      [currentUserId]
    );
    await dbRun(
      "UPDATE users SET is_super_admin = 1, is_promoted_admin = 0 WHERE id = ?",
      [newSuperAdminId]
    );
    await dbRun("COMMIT");
    
    // Update current session
    req.session.isSuperAdmin = false;
    
    // Notify the new Super Admin
    await dbRun(
      "INSERT INTO notifications (user_id, post_id, type, message) VALUES (?, NULL, 'promotion', ?)",
      [newSuperAdminId, '👑 You are now the Super Admin! You have full control over the site and all admins.']
    );

    await logAdminAudit({
      actorAdminId: currentUserId,
      targetUserId: newSuperAdminId,
      actionType: "super_admin_transfer",
      details: `Transferred Super Admin role to @${targetUser.username}`,
    });
    
    res.json({ 
      ok: true, 
      message: `Super Admin status transferred to ${targetUser.username}. You are now a Promoted Admin.`,
      transferred: true
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

// Get current user - UNIFIED: Always use database as single source of truth
app.get("/api/auth/me", async (req, res, next) => {
  try {
    // No session userId = not logged in
    if (!req.session.userId) {
      return res.json({ isAdmin: false, isSuperAdmin: false, isPromotedAdmin: false, userId: null, userRole: null });
    }

    // Always fetch current user data from database (single source of truth)
    const user = await dbGet(
      "SELECT id, username, full_name, email, bio, avatar, is_admin, is_super_admin, is_promoted_admin, email_verified, is_author_verified FROM users WHERE id = ?",
      [req.session.userId]
    );

    if (!user) {
      // User was deleted, clear session
      req.session.destroy();
      return res.json({ isAdmin: false, isSuperAdmin: false, isPromotedAdmin: false, userId: null, userRole: null });
    }

    // Update session to match database (keeps session in sync with DB changes like promotions/demotions)
    req.session.isAdmin = user.is_admin === 1;
    req.session.isSuperAdmin = user.is_super_admin === 1;
    req.session.isPromotedAdmin = user.is_promoted_admin === 1;
    req.session.userRole = user.is_admin === 1 ? "admin" : "user";
    req.session.emailVerified = user.email_verified === 1;

    // Return unified response format
    return res.json({
      id: user.id,
      userId: user.id,
      username: user.username,
      fullName: user.full_name || '',
      full_name: user.full_name || '',
      email: user.email || '',
      bio: user.bio || '',
      avatar: user.avatar || '',
      isAdmin: user.is_admin === 1,
      isSuperAdmin: user.is_super_admin === 1,
      isPromotedAdmin: user.is_promoted_admin === 1,
      isAuthorVerified: user.is_author_verified === 1,
      userRole: user.is_admin === 1 ? "admin" : "user",
      emailVerified: user.email_verified === 1
    });
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

    const user = await dbGet("SELECT id, username, email, full_name, bio, created_at, avatar, is_admin, email_verified, is_author_verified, author_verified_by_admin_id, author_verified_at FROM users WHERE id = ?", [userId]);
    if (!user) return res.status(404).json({ error: "User not found" });

    // Get user's posts (include posts by this user, even if they're an admin)
    const posts = await dbAll("SELECT id, title, body, created_at, tags FROM posts WHERE author_id = ? ORDER BY created_at DESC", [userId]);

    // Get user's comments with post context
    const comments = await dbAll(
      `SELECT c.id, c.post_id, c.body, c.created_at, c.updated_at, p.title as post_title
       FROM comments c
       JOIN posts p ON p.id = c.post_id
       WHERE c.user_id = ?
       ORDER BY c.created_at DESC`,
      [userId]
    );

    res.json({ 
      id: user.id, 
      username: user.username, 
      email: user.email, 
      full_name: user.full_name, 
      bio: user.bio, 
      avatar: user.avatar || "", 
      created_at: user.created_at, 
      is_admin: user.is_admin === 1,
      email_verified: user.email_verified === 1,
      is_author_verified: user.is_author_verified === 1,
      author_verified_by_admin_id: user.author_verified_by_admin_id || null,
      author_verified_at: user.author_verified_at || null,
      posts, 
      comments 
    });
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

    if (bio.length > MAX_BIO_CHARS) {
      return res.status(400).json({ error: `Bio must be ${MAX_BIO_CHARS} characters or less` });
    }

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

// Change password for regular users / promoted admins (requires old password)
app.put("/api/auth/change-password", requireAuth, async (req, res, next) => {
  try {
    const oldPassword = (req.body.oldPassword || "").toString();
    const newPassword = (req.body.newPassword || "").toString();
    const confirmPassword = (req.body.confirmPassword || "").toString();

    if (!oldPassword) return res.status(400).json({ error: "Current password is required" });
    if (!newPassword) return res.status(400).json({ error: "New password is required" });
    if (newPassword.length < 6) return res.status(400).json({ error: "New password must be at least 6 characters" });
    if (newPassword !== confirmPassword) return res.status(400).json({ error: "New passwords do not match" });

    // Super admins use the admin credentials page instead
    if (req.session.isSuperAdmin) {
      return res.status(403).json({ error: "Super Admins should use the admin credentials page" });
    }

    const user = await dbGet("SELECT id, password_hash FROM users WHERE id = ?", [req.session.userId]);
    if (!user) return res.status(404).json({ error: "User not found" });

    const valid = await verifyPassword(oldPassword, user.password_hash, user.id);
    if (!valid) return res.status(401).json({ error: "Current password is incorrect" });

    const newHash = await hashPassword(newPassword);
    await dbRun("UPDATE users SET password_hash = ? WHERE id = ?", [newHash, user.id]);

    res.json({ ok: true, message: "Password updated successfully" });
  } catch (err) {
    next(err);
  }
});

app.get("/api/posts", async (req, res, next) => {
  try {
    const userId = req.session.userId || null;
    const params = [];
    const bookmarkSelect = userId
      ? "EXISTS(SELECT 1 FROM bookmarks b WHERE b.post_id = p.id AND b.user_id = ?) as is_bookmarked"
      : "0 as is_bookmarked";
    if (userId) params.push(userId);

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
          ELSE COALESCE(u.is_admin, 0)
        END as author_is_admin,
        COALESCE(u.email_verified, 0) as author_email_verified,
        CASE
          WHEN p.author_id IS NULL THEN 1
          ELSE COALESCE(u.is_author_verified, 0)
        END as author_is_verified_by_admin,
        COALESCE(u.author_verified_by_admin_id, NULL) as author_verified_by_admin_id,
        COALESCE(verifier.username, '') as author_verified_by_admin_name,
        u.author_verified_at as author_verified_at,
        CASE 
          WHEN p.author_id IS NULL THEN 1
          ELSE 0
        END as is_admin_post,
        COALESCE((SELECT COUNT(*) FROM comments WHERE post_id = p.id), 0) as comment_count,
        COALESCE((SELECT COUNT(*) FROM reactions WHERE post_id = p.id AND reaction_type = 'useful'), 0) as useful_count,
        COALESCE((SELECT COUNT(*) FROM reactions WHERE post_id = p.id AND reaction_type = 'notuseful'), 0) as notuseful_count,
        ${bookmarkSelect}
      FROM posts p
      LEFT JOIN users u ON p.author_id = u.id
      LEFT JOIN users verifier ON verifier.id = u.author_verified_by_admin_id
      ORDER BY p.id DESC
    `, params);
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

    const userId = req.session.userId || null;
    const params = [];
    const bookmarkSelect = userId
      ? "EXISTS(SELECT 1 FROM bookmarks b WHERE b.post_id = p.id AND b.user_id = ?) as is_bookmarked"
      : "0 as is_bookmarked";
    if (userId) params.push(userId);

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
          ELSE COALESCE(u.is_admin, 0)
        END as author_is_admin,
        COALESCE(u.email_verified, 0) as author_email_verified,
        CASE
          WHEN p.author_id IS NULL THEN 1
          ELSE COALESCE(u.is_author_verified, 0)
        END as author_is_verified_by_admin,
        COALESCE(u.author_verified_by_admin_id, NULL) as author_verified_by_admin_id,
        COALESCE(verifier.username, '') as author_verified_by_admin_name,
        u.author_verified_at as author_verified_at,
        CASE 
          WHEN p.author_id IS NULL THEN 1
          ELSE 0
        END as is_admin_post,
        COALESCE((SELECT COUNT(*) FROM comments WHERE post_id = p.id), 0) as comment_count,
        COALESCE((SELECT COUNT(*) FROM reactions WHERE post_id = p.id AND reaction_type = 'useful'), 0) as useful_count,
        COALESCE((SELECT COUNT(*) FROM reactions WHERE post_id = p.id AND reaction_type = 'notuseful'), 0) as notuseful_count,
        ${bookmarkSelect}
      FROM posts p
      LEFT JOIN users u ON p.author_id = u.id
      LEFT JOIN users verifier ON verifier.id = u.author_verified_by_admin_id
      WHERE p.id = ?
    `, [...params, id]);

    if (rows.length === 0) {
      return res.status(404).json({ error: "Post not found" });
    }

    res.json(rows[0]);
  } catch (err) {
    next(err);
  }
});

// Edit a post with permission checks
// Admin can edit: (a) their own authored posts, or (b) legacy admin posts with NULL author_id
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
      // Admin can edit their own authored posts and legacy NULL-author admin posts
      if (post.author_id !== null && post.author_id !== req.session.userId) {
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
    const category = req.body.category || null;
    if (!Array.isArray(tags)) {
      tags = tags.toString().split(',').map(s => s.trim()).filter(Boolean);
    }
    const normalizedTags = normalizePostTags(tags, category);

    if (!title || !body) return res.status(400).json({ error: "Title and body are required" });
    const bodyWordCount = countWords(body);
    if (bodyWordCount > MAX_POST_WORDS) {
      return res.status(400).json({ error: `Post content must be ${MAX_POST_WORDS} words or less` });
    }

    const result = await dbRun("UPDATE posts SET title = ?, body = ?, tags = ? WHERE id = ?", [title, body, JSON.stringify(normalizedTags), id]);
    if (!result.changes) return res.status(404).json({ error: "Post not found" });

    const rows = await dbAll(`
      SELECT p.id, p.title, p.body, p.created_at, p.tags, p.is_flagged,
        CASE WHEN p.author_id IS NULL THEN '@admin' ELSE u.username END as author_name,
        COALESCE(u.avatar, '') as author_avatar,
        COALESCE(u.email_verified, 0) as author_email_verified,
        CASE WHEN p.author_id IS NULL THEN 1 ELSE COALESCE(u.is_admin, 0) END as author_is_admin,
        CASE WHEN p.author_id IS NULL THEN 1 ELSE COALESCE(u.is_author_verified, 0) END as author_is_verified_by_admin,
        COALESCE(u.author_verified_by_admin_id, NULL) as author_verified_by_admin_id,
        COALESCE(verifier.username, '') as author_verified_by_admin_name,
        u.author_verified_at as author_verified_at,
        CASE WHEN p.author_id IS NULL THEN 1 ELSE 0 END as is_admin_post
      FROM posts p
      LEFT JOIN users u ON p.author_id = u.id
      LEFT JOIN users verifier ON verifier.id = u.author_verified_by_admin_id
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

    // All users (including admins) use their userId as author_id
    // Admins are identified by the is_admin flag on the user, not by NULL author_id
    const authorId = req.session.userId || null;

    const title = (req.body.title || "").toString().trim();
    const body = (req.body.body || "").toString().trim();
    let tags = req.body.tags || [];
    const category = req.body.category || null;
    if (!Array.isArray(tags)) {
      tags = tags.toString().split(',').map(s => s.trim()).filter(Boolean);
    }
    const normalizedTags = normalizePostTags(tags, category);

    if (!title || !body) return res.status(400).json({ error: "Title and body are required" });
    const bodyWordCount = countWords(body);
    if (bodyWordCount > MAX_POST_WORDS) {
      return res.status(400).json({ error: `Post content must be ${MAX_POST_WORDS} words or less` });
    }

    const result = await dbRun("INSERT INTO posts (author_id, title, body, tags) VALUES (?, ?, ?, ?) RETURNING id", 
      [authorId, title, body, JSON.stringify(normalizedTags)]);

    // Return created resource including author info
    const created = await dbGet(`
      SELECT p.id, p.title, p.body, p.created_at, p.tags, p.is_flagged,
        CASE WHEN p.author_id IS NULL THEN '@admin' ELSE u.username END as author_name,
        COALESCE(u.avatar, '') as author_avatar,
        COALESCE(u.email_verified, 0) as author_email_verified,
        CASE WHEN p.author_id IS NULL THEN 1 ELSE COALESCE(u.is_admin, 0) END as author_is_admin,
        CASE WHEN p.author_id IS NULL THEN 1 ELSE COALESCE(u.is_author_verified, 0) END as author_is_verified_by_admin,
        COALESCE(u.author_verified_by_admin_id, NULL) as author_verified_by_admin_id,
        COALESCE(verifier.username, '') as author_verified_by_admin_name,
        u.author_verified_at as author_verified_at,
        CASE WHEN p.author_id IS NULL THEN 1 ELSE 0 END as is_admin_post
      FROM posts p
      LEFT JOIN users u ON p.author_id = u.id
      LEFT JOIN users verifier ON verifier.id = u.author_verified_by_admin_id
      WHERE p.id = ?
    `, [result.lastID]);

    const actorUsername = req.session.username || (req.session.isAdmin ? "admin" : "someone");
    await notifyMentions({ actorId: req.session.userId || null, actorUsername, text: `${title}\n${body}`, postId: result.lastID });

    res.status(201).json(normalizePostRow(created));
  } catch (err) {
    next(err);
  }
});

// --------- COMMENTS ENDPOINTS ---------
const MAX_COMMENT_REPLY_DEPTH = 8;

// Get all comments for a post
app.get('/api/posts/:postId/comments', async (req, res, next) => {
  try {
    const postId = Number(req.params.postId);
    if (!Number.isInteger(postId) || postId <= 0) return res.status(400).json({ error: "Invalid post id" });

    const comments = await dbAll(`
      SELECT c.id, c.post_id, c.user_id, c.parent_comment_id, c.body, c.created_at, c.updated_at, u.username, COALESCE(u.avatar, '') as avatar, COALESCE(u.is_admin, 0) as is_admin
      FROM comments c
      JOIN users u ON c.user_id = u.id
      WHERE c.post_id = ?
      ORDER BY c.created_at ASC, c.id ASC
    `, [postId]);

    res.json(comments);
  } catch (err) {
    next(err);
  }
});

// Create a comment (requires auth)
app.post('/api/posts/:postId/comments', requireAuth, requireVerified, async (req, res, next) => {
  try {
    const postId = Number(req.params.postId);
    if (!Number.isInteger(postId) || postId <= 0) return res.status(400).json({ error: "Invalid post id" });

    const body = (req.body.body || "").toString().trim();
    if (!body) return res.status(400).json({ error: "Comment body is required" });
    const commentWordCount = countWords(body);
    if (commentWordCount > MAX_COMMENT_WORDS) {
      return res.status(400).json({ error: `Comments and replies must be ${MAX_COMMENT_WORDS} words or less` });
    }

    const rawParentCommentId = req.body.parentCommentId;
    const parentCommentId = rawParentCommentId == null || rawParentCommentId === ''
      ? null
      : Number(rawParentCommentId);
    if (parentCommentId != null && (!Number.isInteger(parentCommentId) || parentCommentId <= 0)) {
      return res.status(400).json({ error: "Invalid parent comment id" });
    }

    // Check post exists
    const post = await dbGet("SELECT id, author_id FROM posts WHERE id = ?", [postId]);
    if (!post) return res.status(404).json({ error: "Post not found" });

    if (parentCommentId != null) {
      const parentComment = await dbGet(
        "SELECT id, post_id, user_id FROM comments WHERE id = ?",
        [parentCommentId]
      );
      if (!parentComment) return res.status(404).json({ error: "Parent comment not found" });
      if (Number(parentComment.post_id) !== postId) {
        return res.status(400).json({ error: "Parent comment does not belong to this post" });
      }

      const depthRow = await dbGet(`
        WITH RECURSIVE ancestry AS (
          SELECT id, parent_comment_id, 1 AS depth
          FROM comments
          WHERE id = ?
          UNION ALL
          SELECT c.id, c.parent_comment_id, ancestry.depth + 1
          FROM comments c
          JOIN ancestry ON ancestry.parent_comment_id = c.id
        )
        SELECT MAX(depth) AS max_depth FROM ancestry
      `, [parentCommentId]);

      const parentDepth = Number(depthRow?.max_depth || 1);
      if (parentDepth >= MAX_COMMENT_REPLY_DEPTH) {
        return res.status(400).json({ error: `Maximum reply depth reached (${MAX_COMMENT_REPLY_DEPTH})` });
      }

      if (parentComment.user_id && parentComment.user_id !== req.session.userId) {
        const actorName = req.session.username || 'Someone';
        await createNotification({
          userId: parentComment.user_id,
          postId,
          type: 'comment',
          message: `${actorName} replied to your comment.`
        });
      }
    }

    const result = await dbRun(
      "INSERT INTO comments (post_id, user_id, parent_comment_id, body) VALUES (?, ?, ?, ?) RETURNING id",
      [postId, req.session.userId, parentCommentId, body]
    );

    const comment = await dbGet(`
      SELECT c.id, c.post_id, c.user_id, c.parent_comment_id, c.body, c.created_at, c.updated_at, u.username
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
    const commentWordCount = countWords(body);
    if (commentWordCount > MAX_COMMENT_WORDS) {
      return res.status(400).json({ error: `Comments and replies must be ${MAX_COMMENT_WORDS} words or less` });
    }

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
      SELECT c.id, c.post_id, c.user_id, c.parent_comment_id, c.body, c.created_at, c.updated_at, u.username
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
app.post('/api/posts/:postId/reactions', requireAuth, requireVerified, async (req, res, next) => {
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

// --------- NOTIFICATIONS ---------
app.get('/api/notifications', requireAuth, async (req, res, next) => {
  try {
    const rows = await dbAll(`
      SELECT n.id, n.post_id, n.type, n.message, n.is_read, n.created_at, COALESCE(p.title, '') as post_title
      FROM notifications n
      LEFT JOIN posts p ON n.post_id = p.id
      WHERE n.user_id = ?
      ORDER BY n.created_at DESC
      LIMIT 100
    `, [req.session.userId]);
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

app.patch('/api/notifications/:id/read', requireAuth, async (req, res, next) => {
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

app.delete('/api/notifications/:id', requireAuth, async (req, res, next) => {
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

// --------- BOOKMARKS ENDPOINTS ---------
// Toggle bookmark for a post (user only)
app.post('/api/posts/:postId/bookmark', requireUserOnly, async (req, res, next) => {
  try {
    const postId = Number(req.params.postId);
    if (!Number.isInteger(postId) || postId <= 0) return res.status(400).json({ error: "Invalid post id" });

    const post = await dbGet("SELECT id FROM posts WHERE id = ?", [postId]);
    if (!post) return res.status(404).json({ error: "Post not found" });

    const existing = await dbGet(
      "SELECT id FROM bookmarks WHERE post_id = ? AND user_id = ?",
      [postId, req.session.userId]
    );

    if (existing) {
      await dbRun("DELETE FROM bookmarks WHERE id = ?", [existing.id]);
      return res.json({ ok: true, bookmarked: false });
    }

    await dbRun(
      "INSERT INTO bookmarks (post_id, user_id) VALUES (?, ?)",
      [postId, req.session.userId]
    );
    return res.json({ ok: true, bookmarked: true });
  } catch (err) {
    next(err);
  }
});

// Get bookmark status for a post (user only)
app.get('/api/posts/:postId/bookmark', requireUserOnly, async (req, res, next) => {
  try {
    const postId = Number(req.params.postId);
    if (!Number.isInteger(postId) || postId <= 0) return res.status(400).json({ error: "Invalid post id" });

    const existing = await dbGet(
      "SELECT id FROM bookmarks WHERE post_id = ? AND user_id = ?",
      [postId, req.session.userId]
    );

    res.json({ bookmarked: !!existing });
  } catch (err) {
    next(err);
  }
});

// Get all bookmarks for current user
app.get('/api/bookmarks', requireUserOnly, async (req, res, next) => {
  try {
    const rows = await dbAll(`
      SELECT p.id, p.title, p.body, p.created_at, p.tags, p.is_flagged,
        CASE WHEN p.author_id IS NULL THEN '@admin' ELSE u.username END as author_name,
        COALESCE(u.avatar, '') as author_avatar,
        COALESCE(u.email_verified, 0) as author_email_verified,
        CASE WHEN p.author_id IS NULL THEN 1 ELSE COALESCE(u.is_admin, 0) END as author_is_admin,
        CASE WHEN p.author_id IS NULL THEN 1 ELSE COALESCE(u.is_author_verified, 0) END as author_is_verified_by_admin,
        COALESCE(u.author_verified_by_admin_id, NULL) as author_verified_by_admin_id,
        COALESCE(verifier.username, '') as author_verified_by_admin_name,
        u.author_verified_at as author_verified_at,
        CASE WHEN p.author_id IS NULL THEN 1 ELSE 0 END as is_admin_post,
        COALESCE((SELECT COUNT(*) FROM comments WHERE post_id = p.id), 0) as comment_count,
        COALESCE((SELECT COUNT(*) FROM reactions WHERE post_id = p.id AND reaction_type = 'useful'), 0) as useful_count,
        COALESCE((SELECT COUNT(*) FROM reactions WHERE post_id = p.id AND reaction_type = 'notuseful'), 0) as notuseful_count,
        1 as is_bookmarked,
        b.created_at as bookmarked_at
      FROM bookmarks b
      JOIN posts p ON b.post_id = p.id
      LEFT JOIN users u ON p.author_id = u.id
      LEFT JOIN users verifier ON verifier.id = u.author_verified_by_admin_id
      WHERE b.user_id = ?
      ORDER BY b.created_at DESC
    `, [req.session.userId]);

    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// Search endpoint: search by title/body/tags or author username (case-insensitive LIKE, tokenized AND logic, @username shortcut)
app.get('/api/search', async (req, res, next) => {
  try {
    const qRaw = (req.query.q || '').toString().trim();
    const q = qRaw.toLowerCase();
    const userId = req.session.userId || null;
    const bookmarkSelect = userId
      ? "EXISTS(SELECT 1 FROM bookmarks b WHERE b.post_id = p.id AND b.user_id = ?) as is_bookmarked"
      : "0 as is_bookmarked";

    // If no query, return latest posts
    if (!q) {
      const params = [];
      if (userId) params.push(userId);
      const rows = await dbAll(`
        SELECT p.id, p.title, p.body, p.created_at, p.tags, p.is_flagged,
          CASE WHEN p.author_id IS NULL THEN '@admin' ELSE u.username END as author_name,
          COALESCE(u.avatar, '') as author_avatar,
          COALESCE(u.email_verified, 0) as author_email_verified,
          CASE WHEN p.author_id IS NULL THEN 1 ELSE COALESCE(u.is_admin, 0) END as author_is_admin,
          CASE WHEN p.author_id IS NULL THEN 1 ELSE COALESCE(u.is_author_verified, 0) END as author_is_verified_by_admin,
          COALESCE(u.author_verified_by_admin_id, NULL) as author_verified_by_admin_id,
          COALESCE(verifier.username, '') as author_verified_by_admin_name,
          u.author_verified_at as author_verified_at,
          CASE WHEN p.author_id IS NULL THEN 1 ELSE 0 END as is_admin_post,
          COALESCE((SELECT COUNT(*) FROM comments WHERE post_id = p.id), 0) as comment_count,
          COALESCE((SELECT COUNT(*) FROM reactions WHERE post_id = p.id AND reaction_type = 'useful'), 0) as useful_count,
          COALESCE((SELECT COUNT(*) FROM reactions WHERE post_id = p.id AND reaction_type = 'notuseful'), 0) as notuseful_count,
          ${bookmarkSelect}
        FROM posts p
        LEFT JOIN users u ON p.author_id = u.id
        LEFT JOIN users verifier ON verifier.id = u.author_verified_by_admin_id
        ORDER BY p.id DESC
      `, params);
      return res.json(rows);
    }

    // If query starts with @, prefer author-targeted search
    if (qRaw.startsWith('@') && q.length > 1) {
      const handle = q.replace(/^@+/, '');
      const handleLike = `%${handle}%`;
      const params = [];
      if (userId) params.push(userId);
      const rows = await dbAll(
        `
          SELECT p.id, p.title, p.body, p.created_at, p.tags, p.is_flagged,
            CASE WHEN p.author_id IS NULL THEN '@admin' ELSE u.username END as author_name,
            COALESCE(u.avatar, '') as author_avatar,
            COALESCE(u.email_verified, 0) as author_email_verified,
            CASE WHEN p.author_id IS NULL THEN 1 ELSE COALESCE(u.is_admin, 0) END as author_is_admin,
            CASE WHEN p.author_id IS NULL THEN 1 ELSE COALESCE(u.is_author_verified, 0) END as author_is_verified_by_admin,
            COALESCE(u.author_verified_by_admin_id, NULL) as author_verified_by_admin_id,
            COALESCE(verifier.username, '') as author_verified_by_admin_name,
            u.author_verified_at as author_verified_at,
            CASE WHEN p.author_id IS NULL THEN 1 ELSE 0 END as is_admin_post,
            COALESCE((SELECT COUNT(*) FROM comments WHERE post_id = p.id), 0) as comment_count,
            COALESCE((SELECT COUNT(*) FROM reactions WHERE post_id = p.id AND reaction_type = 'useful'), 0) as useful_count,
            COALESCE((SELECT COUNT(*) FROM reactions WHERE post_id = p.id AND reaction_type = 'notuseful'), 0) as notuseful_count,
            ${bookmarkSelect}
          FROM posts p
          LEFT JOIN users u ON p.author_id = u.id
           LEFT JOIN users verifier ON verifier.id = u.author_verified_by_admin_id
          WHERE (p.author_id IS NULL AND '@admin' LIKE ?)
             OR lower(u.username) LIKE ?
          ORDER BY p.id DESC
        `,
        [...params, handleLike, handleLike]
      );
      return res.json(rows);
    }

    // Tokenized AND search across title/body/tags/author
    const tokens = q.split(/\s+/).filter(Boolean);
    const clauses = [];
    const params = [];
    if (userId) params.push(userId);

    tokens.forEach((token) => {
      const like = `%${token}%`;
      clauses.push(`(lower(p.title) LIKE ? OR lower(p.body) LIKE ? OR lower(p.tags) LIKE ? OR lower(COALESCE(u.username, '@admin')) LIKE ?)`);
      params.push(like, like, like, like);
    });

    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';

    const rows = await dbAll(
      `
        SELECT p.id, p.title, p.body, p.created_at, p.tags, p.is_flagged,
          CASE WHEN p.author_id IS NULL THEN '@admin' ELSE u.username END as author_name,
          COALESCE(u.avatar, '') as author_avatar,
          COALESCE(u.email_verified, 0) as author_email_verified,
          CASE WHEN p.author_id IS NULL THEN 1 ELSE COALESCE(u.is_admin, 0) END as author_is_admin,
          CASE WHEN p.author_id IS NULL THEN 1 ELSE COALESCE(u.is_author_verified, 0) END as author_is_verified_by_admin,
          COALESCE(u.author_verified_by_admin_id, NULL) as author_verified_by_admin_id,
          COALESCE(verifier.username, '') as author_verified_by_admin_name,
          u.author_verified_at as author_verified_at,
          CASE WHEN p.author_id IS NULL THEN 1 ELSE 0 END as is_admin_post,
          COALESCE((SELECT COUNT(*) FROM comments WHERE post_id = p.id), 0) as comment_count,
          COALESCE((SELECT COUNT(*) FROM reactions WHERE post_id = p.id AND reaction_type = 'useful'), 0) as useful_count,
          COALESCE((SELECT COUNT(*) FROM reactions WHERE post_id = p.id AND reaction_type = 'notuseful'), 0) as notuseful_count,
          ${bookmarkSelect}
        FROM posts p
        LEFT JOIN users u ON p.author_id = u.id
        LEFT JOIN users verifier ON verifier.id = u.author_verified_by_admin_id
        ${where}
        ORDER BY p.id DESC
      `,
      params
    );

    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// Basic homepage route (optional)
app.get("/admin-login.html", (req, res) => {
  res.redirect("/login.html?mode=admin");
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// --------- EMAIL VERIFICATION ENDPOINTS ---------
const verifyLimiter = createRateLimiter({ limit: 5, windowMs: 15 * 60 * 1000 });
const resendLimiter = createRateLimiter({ limit: 3, windowMs: 5 * 60 * 1000 });

// Verify email with 6-digit code
app.post("/api/auth/verify-email", requireAuth, verifyLimiter, async (req, res, next) => {
  try {
    const code = (req.body.code || "").toString().trim();
    if (!code || code.length !== 6) {
      return res.status(400).json({ error: "Please enter a valid 6-digit code" });
    }

    const user = await dbGet(
      "SELECT id, email_verified, verification_code, verification_code_expires FROM users WHERE id = ?",
      [req.session.userId]
    );
    if (!user) return res.status(404).json({ error: "User not found" });

    if (user.email_verified === 1) {
      req.session.emailVerified = true;
      return res.json({ ok: true, message: "Email is already verified" });
    }

    if (!user.verification_code || !user.verification_code_expires) {
      return res.status(400).json({ error: "No verification code found. Please request a new one." });
    }

    // Check expiry
    if (new Date(user.verification_code_expires) < new Date()) {
      return res.status(400).json({ error: "Verification code has expired. Please request a new one." });
    }

    // Compare hashed code
    const hashedInput = hashVerificationCode(code);
    if (hashedInput !== user.verification_code) {
      return res.status(400).json({ error: "Invalid verification code" });
    }

    // Mark email as verified and clear code
    await dbRun(
      "UPDATE users SET email_verified = 1, verification_code = '', verification_code_expires = '' WHERE id = ?",
      [user.id]
    );

    req.session.emailVerified = true;
    req.session.save((err) => {
      if (err) console.error("[session] save error after verification:", err);
      res.json({ ok: true, message: "Email verified successfully!" });
    });
  } catch (err) {
    next(err);
  }
});

// Resend verification code
app.post("/api/auth/resend-verification", requireAuth, resendLimiter, async (req, res, next) => {
  try {
    const user = await dbGet(
      "SELECT id, email, username, email_verified FROM users WHERE id = ?",
      [req.session.userId]
    );
    if (!user) return res.status(404).json({ error: "User not found" });

    if (user.email_verified === 1) {
      req.session.emailVerified = true;
      return res.json({ ok: true, message: "Email is already verified" });
    }

    // Generate new code
    const verificationCode = generateVerificationCode();
    const hashedCode = hashVerificationCode(verificationCode);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    await dbRun(
      "UPDATE users SET verification_code = ?, verification_code_expires = ? WHERE id = ?",
      [hashedCode, expiresAt, user.id]
    );

    await sendVerificationCode(user.email, verificationCode, user.username);

    res.json({ ok: true, message: "Verification code sent! Check your email." });
  } catch (err) {
    next(err);
  }
});

// Centralized error handler
app.use((err, req, res, next) => {
  console.error(err && err.stack ? err.stack : err);
  res.status(500).json({ error: err && err.message ? err.message : 'Internal server error' });
});

const PORT = process.env.PORT || 3000;

// Wait for database schema to be ready, then bootstrap admin, then start listening
db.initPromise
  .then(async () => {
    console.log("[startup] Database schema ready");
    try {
      const admin = await ensureAdminUser();
      console.log("[startup] Admin user ready:", admin ? admin.username : "(none)");
    } catch (err) {
      console.error("[startup] Failed to bootstrap admin user:", err.message);
    }
    app.listen(PORT, () => {
      console.log(`Server listening on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error("[startup] Database initialization failed:", err);
    process.exit(1);
  });
