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
- `ADMIN_USERNAME` (optional; default `@admin` for first-time bootstrap)
- `ADMIN_PASSWORD` (strongly recommended in production; used only when no admin exists yet)
- `ADMIN_EMAIL` (optional; default `admin@example.local`)
- `ADMIN_RESET_ON_BOOT=1` (optional recovery mode: if a super admin already exists, reset its credentials from `ADMIN_*` on startup)

Admin bootstrap behavior:
- On first startup, if no admin exists, the app creates one.
- If `ADMIN_USERNAME` and `ADMIN_PASSWORD` are set, those are used.
- If `ADMIN_PASSWORD` is missing, a random password is generated. In production, the value is hidden in logs, so set `ADMIN_PASSWORD` explicitly on Render.
- Recovery for existing deployments: set `ADMIN_RESET_ON_BOOT=1` + `ADMIN_PASSWORD` (and optionally `ADMIN_USERNAME`/`ADMIN_EMAIL`), deploy once, log in, then set `ADMIN_RESET_ON_BOOT=0` and deploy again.

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

## Deploying/selling on Gumroad
- Ship the full source; buyer runs `npm install && SESSION_SECRET=... node server.js`.
- Provide a strong `SESSION_SECRET` per deployment and run behind HTTPS; set `TRUST_PROXY=1` if fronted by a proxy.
- Bundle a short setup note about the generated admin temp password on first run and the need to rotate it.
- If you need persistence across restarts/backups, keep `blog.db` and stdout logs.

## Support
This is offered as-is. For production use, add backups, logging, HTTPS termination, and stronger monitoring/rate-limiting as needed.

## Visuals

<img width="1919" height="893" alt="Screenshot 2026-02-19 210944" src="https://github.com/user-attachments/assets/eecccafc-3fa9-4732-a492-c53ff318c762" />

<img width="1919" height="892" alt="Screenshot 2026-02-19 211005" src="https://github.com/user-attachments/assets/e1b7746c-9e34-44e2-a63d-3f8f28ef7420" />

<img width="1919" height="882" alt="Screenshot 2026-02-19 211055" src="https://github.com/user-attachments/assets/740509e9-5124-4614-9b4f-eb70ac288a00" />

<img width="1919" height="885" alt="Screenshot 2026-02-19 211120" src="https://github.com/user-attachments/assets/86dab6ed-20f6-4af1-a300-d4a82f86d280" />

<img width="1920" height="1549" alt="screencapture-localhost-3000-create-post-html-2026-02-19-21_13_02" src="https://github.com/user-attachments/assets/a27e72c5-ca11-416b-8aa5-3e3575712f2f" />

<img width="1920" height="1080" alt="Screenshot 2026-02-19 211157" src="https://github.com/user-attachments/assets/f1e77e3d-c55c-4a61-a406-77197db63a7b" />

<img width="1919" height="874" alt="Screenshot 2026-02-19 211336" src="https://github.com/user-attachments/assets/8be88931-8239-4f7e-b3bf-9c49c6c39d52" />

<img width="1919" height="875" alt="Screenshot 2026-02-19 211402" src="https://github.com/user-attachments/assets/fc4b8d72-202e-4886-9131-c8fefb1defbb" />

<img width="1919" height="872" alt="Screenshot 2026-02-19 211452" src="https://github.com/user-attachments/assets/104eb85e-d372-4d42-8c37-92486446072b" />

<img width="1919" height="876" alt="Screenshot 2026-02-19 211512" src="https://github.com/user-attachments/assets/acbf51de-cb70-4838-a457-ac526d9b3d07" />

<img width="1919" height="874" alt="Screenshot 2026-02-19 211539" src="https://github.com/user-attachments/assets/7b54633c-95f3-4956-a35f-7bd8c795e8d7" />

