# Dynamic Blogs

A small Express + SQLite blog/playground with basic accounts, admin moderation, comments, reactions, and notifications. Ideal for students, indie hackers, and developers who want a simple, framework-free Node.js app to extend and customize.


## What this webapp is
- A self-hosted blog with user registration/login and session-based auth.
- Supports creating/editing/deleting posts (users manage their own, admin can post as @admin and moderate all).
- Commenting, useful/not useful reactions, and per-user notifications.
- Admin dashboard to list users, flag/unflag posts, and delete content.
- Profile editing with selectable avatars and short bios.
- SQLite-backed with auto-migrations on startup; ships as a single Node server.
- Ships with basic security hardening: bcrypt hashing (legacy migration included), CSRF tokens, rate limiting, secure cookies, and safety headers.

## What this webapp is NOT
- Not a multi-tenant SaaS or hosted service; you run it yourself.
- Not production-grade for regulated data (HIPAA/PCI/FERPA/GDPR-sensitive use is out of scope).
- Not battle-tested for large scale or hostile environments; security is best-effort for a small app.
- Not an email/notifications delivery system (no outbound email/SMS built in).
- Not offering SSO/OAuth, password reset, 2FA, or multi-language support.

## Stack
- Node.js, Express 5, express-session
- SQLite (file: `blog.db`) via `sqlite3`
- bcryptjs for password hashing
- Plain HTML/CSS/JS frontend served from `public/`

## Requirements
- Node.js 18+ recommended
- npm (for dependency install)
- Disk write access for `blog.db`

## Quick start (local)
```
npm install
npm start
```
The app starts on http://localhost:3000. In production, set a strong SESSION_SECRET and run behind HTTPS.

## Usage highlights
- Users: register, log in, create/edit/delete their own posts; comment and react; view notifications.
- Admin: log in at `/admin-login.html`, create admin posts, flag/unflag or delete any post, list users.
- Profiles: edit name, email, bio, avatar from `/profile.html` or `/edit-profile.html`.

## Configuration
Environment variables you can set:
- `PORT` (default 3000)
- `SESSION_SECRET` (required in production; min 16 chars)
- `SESSION_NAME` (cookie name; default `sid`)
- `NODE_ENV` (`production` enables secure cookies + HSTS header)
- `TRUST_PROXY=1` when running behind a reverse proxy to honor secure cookies
- `BCRYPT_ROUNDS` (8-14; default 12)

## Data & storage
- SQLite file: `blog.db` in the project root
- Tables: users, posts, comments, reactions, notifications
- Admin posts store `author_id` as NULL to distinguish them
- No email delivery or file uploads

## Security notes
- Passwords hashed with bcrypt; legacy SHA-256 hashes auto-migrate on successful login.
- CSRF protection via per-session token and client helper in `public/csrf.js`.
- Session cookies are httpOnly, SameSite=strict; `secure` set when NODE_ENV=production.
- Simple in-memory rate limiters on auth and write endpoints; restart clears counters.
- Security headers: CSP, X-Frame-Options DENY, Referrer-Policy same-origin, X-Content-Type-Options nosniff, HSTS in production.
- Admin actions (delete/flag) log to stdout for audit visibility; stdout should be persisted in production.

## Intentional Limitations
- No email verification, password reset, or MFA.
- No media storage/uploads; posts are text-only.
- No WYSIWYG editor; body is plain text.
- No search indexing beyond simple SQL LIKE.
- No horizontal scaling; single-instance with in-memory rate limits.

## Deploying / selling on Gumroad
- Ship the full source; buyer runs `npm install && SESSION_SECRET=... node server.js`.
- Provide a strong `SESSION_SECRET` per deployment and run behind HTTPS; set `TRUST_PROXY=1` if fronted by a proxy.
- Bundle a short setup note about the generated admin temp password on first run and the need to rotate it.
- If you need persistence across restarts/backups, keep `blog.db` and stdout logs.

## Support
This is offered as-is. For production use, add backups, logging, HTTPS termination, and stronger monitoring/rate-limiting as needed.
