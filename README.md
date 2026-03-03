# Dynamic Blogs

Dynamic Blogs is a production-minded full-stack blogging platform built with Express, PostgreSQL, and a vanilla HTML/CSS/JS frontend. It demonstrates end-to-end software engineering across product design, backend architecture, security hardening, role-based administration, and deployment readiness.

## Executive summary
- What it is: a content publishing web app with user/community features and administrative governance.
- Why it matters: it balances engineering depth (auth, moderation, security, data model) with practical business utility (ready-to-deploy blog/SaaS foundation).
- Deployment target: Render + PostgreSQL with environment-based configuration.

## For admissions committees
This project evidences applied software engineering skills beyond CRUD implementation:

- Full-stack ownership: designed and implemented frontend UX, backend API surface, and persistence layer.
- Security engineering: CSRF protection, session security, password hashing, rate limiting, and hardened headers.
- Data modeling: normalized relational schema (users/posts/comments/reactions/bookmarks/notifications/admin audit logs) with index strategy.
- Access control design: layered authorization (user, promoted admin, super admin) with explicit policy enforcement.
- Reliability mindset: health endpoint, startup schema initialization, environment-driven behavior, and deployment hardening for reverse proxies.

## For clients / product buyers
Dynamic Blogs can be sold or used as a strong base for a content business MVP:

- Supports publishing workflows: user posts, moderation tools, and community engagement features.
- Reduces time-to-market: deploy-ready architecture with a clean server entrypoint and static frontend.
- Extensible foundation: easy to add premium features (payments, premium content, analytics, newsletter, media uploads).
- Operationally practical: environment-based config, health checks, and straightforward hosting on Render.
- Cost-aware development: SMTP optional fallback mode allows testing email flows before paying for provider tiers.

## Core features
- Account system: register, login, logout, session auth.
- Post management: create, edit, delete, flag/unflag (admin), category/tag support.
- Discussion layer: threaded comments with replies, edit/delete permissions.
- Engagement: useful/not useful reactions and post bookmarks.
- Notifications: mentions, moderation actions, reactions/comments, and promotion events.
- Profiles: user profile pages, edit profile, avatar presets, password change.
- Search: title/body/tags/author search endpoint for feed filtering.

## Admin system
- Single Super Admin model with promoted admins.
- Admin tools include user listing, author verification controls, admin promotion/demotion, and super-admin transfer.
- Audit trail support for important admin actions.
- Admin credentials can be updated securely through API endpoints.

## Email verification status
- UI and API for email verification are implemented.
- SMTP is optional; when SMTP is not configured, verification codes are logged in server output.
- Enforcement is configurable with `REQUIRE_EMAIL_VERIFICATION`:
	- `0` (default): login-only flow, verification not required for protected write actions.
	- `1`: verified email required for selected write actions.

## Security posture
- Passwords use bcrypt (legacy SHA-256 hashes are migrated on successful login).
- Session cookies are `httpOnly`, `sameSite=strict`, and `secure` in production.
- CSRF protection for mutating requests via token header.
- In-memory rate limiters for auth, verification, resend, and write operations.
- Security headers: CSP, HSTS (prod), X-Frame-Options, nosniff, and referrer policy.

## Architecture snapshot
- Backend entrypoint: `server.js` (Express app, middleware, API routes, startup flow).
- Data layer: `db.js` (PostgreSQL pool, schema bootstrap, wrapper helpers).
- Mail integration: `email.js` (SMTP transporter + fallback behavior).
- Frontend delivery: static pages/scripts under `public/`.

## Tech stack
- Backend: Node.js 18+, Express 5, express-session, pg.
- Database: PostgreSQL.
- Frontend: static HTML pages + vanilla JS + CSS under `public/`.

## Prerequisites
- Node.js 18+
- npm
- PostgreSQL database connection URL

## Quick start
```bash
npm install
```

Create `.env` from `.env.example`:

Windows PowerShell:
```powershell
Copy-Item .env.example .env
```

macOS/Linux:
```bash
cp .env.example .env
```

Start the server:
```bash
npm start
```

App default URL: `http://localhost:3000`

## Environment configuration
Required for deploy:
- `DATABASE_URL`
- `SESSION_SECRET` (16+ chars in production)

Common runtime vars:
- `NODE_ENV` (`production` on Render)
- `PORT` (Render injects this automatically)
- `TRUST_PROXY=1` (recommended behind Render proxy)
- `SESSION_NAME` (optional; default `sid`)
- `BCRYPT_ROUNDS` (default `12`, range `8-14`)
- `REQUIRE_EMAIL_VERIFICATION` (`0` or `1`)

Admin bootstrap vars:
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD`
- `ADMIN_EMAIL`
- `ADMIN_RESET_ON_BOOT=1` (one-time recovery/reset mode)

SMTP vars (optional):
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASS`
- `SMTP_FROM`

## Database behavior
- Schema is auto-initialized at startup.
- Primary tables include users, posts, comments, reactions, bookmarks, notifications, and admin audit logs.
- Indexes are created automatically for common query paths.

## Deploying to Render
Build command:
```bash
npm install
```

Start command:
```bash
npm start
```

Set environment variables in Render dashboard:
- `NODE_ENV=production`
- `DATABASE_URL`
- `SESSION_SECRET`
- `TRUST_PROXY=1`
- Admin bootstrap variables (`ADMIN_USERNAME`, `ADMIN_PASSWORD`, `ADMIN_EMAIL`)

Health check endpoint:
- `/api/health`

## Business-ready use cases
- Digital publication for a personal brand or editorial team.
- Internal knowledge or community portal with moderation controls.
- Starter SaaS for creator platforms where user-generated content is core.
- Portfolio-grade demo for freelance/client acquisition.

## Known limitations
- Rate limiting is in-memory (single-instance behavior).
- No password-reset flow yet.
- No file uploads/media storage.
- No OAuth/SSO.

## Troubleshooting
- Startup fails: check `DATABASE_URL`, PostgreSQL network access, and Node version.
- Login/session issues in production: verify `SESSION_SECRET` and `TRUST_PROXY=1`.
- CSRF errors: ensure frontend includes `public/csrf.js` and sends token on writes.
- Verification email not sent: set SMTP vars or use console fallback logs.
- Admin lockout: use `ADMIN_RESET_ON_BOOT=1` with a new `ADMIN_PASSWORD`, deploy once, then disable it.

## Project notes
- Main server entrypoint: `server.js`
- Static client files: `public/`
- Database layer + schema init: `db.js`
- Email helper: `email.js`

### Visuals

On process... 