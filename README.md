# Dynamic Blogs

Lightweight Express + PostgreSQL blog playground with session auth, admin moderation, comments, reactions, notifications, and basic hardening. Built to be hacked on: no frontend frameworks, plain HTML/CSS/JS, and a single Node server you can read end to end.

## Publication identity
- Mission: Practical ideas and real stories that help people think clearly and grow consistently.
- Content pillars: Mindset, Life Lessons, Discipline, Real Stories, Career.
- Public navigation: Explore, Topics, About, Submit Story.

## Rebuild progress tracker
- Track implementation status for the 5-phase rebuild roadmap in `ROADMAP_PROGRESS.md`.

## Highlights
- Self-hosted blog with registration/login and session-based auth.
- Create, edit, and delete posts; users manage their own content, admin can manage all and post as `@admin`.
- Comment threads, useful/not useful reactions, and per-user notifications.
- Admin dashboard for user list, flag/unflag, and delete actions; audit logs to stdout.
- Profile editing (name, email, bio, avatar) via `/profile.html` and `/edit-profile.html`.
- Security basics baked in: bcrypt hashing (legacy migration), CSRF tokens, rate limiting, secure cookies, and safety headers.

## Not the target
- Not a hosted SaaS; you run it.
- Not suited for regulated data (HIPAA/PCI/FERPA/GDPR-sensitive use is out of scope).
- Not tuned for large scale or hostile traffic; rate limiting is in-memory.
- No outbound email/SMS; no password reset or MFA.
- No OAuth/SSO or multi-language support.

## Tech stack
- Node.js 18+, Express 5, express-session
- PostgreSQL (Supabase free tier recommended) via `pg`
- bcryptjs for password hashing
- Plain HTML/CSS/JS served from `public/`

## Prerequisites
- Node.js 18+ and npm
- PostgreSQL database (supply a `DATABASE_URL`)

## Quick start
```
npm install
cp .env.example .env
npm start
```
The server listens on http://localhost:3000. Provide a valid `DATABASE_URL` and set a strong `SESSION_SECRET` in production.

## Usage
- Users: register, log in, write/edit/delete their own posts; comment and react; view notifications.
- Admin: sign in through the same `/login.html` flow (admin accounts are recognized automatically), post as `@admin`, flag/unflag or delete any post, list users.
- Profiles: update basic info and avatar from `/profile.html` or `/edit-profile.html`.

## Configuration
Environment variables:
- `PORT` (default 3000)
- `SESSION_SECRET` (required in production; min 16 chars)
- `SESSION_NAME` (cookie name; default `sid`)
- `NODE_ENV` (`production` enables secure cookies + HSTS)
- `TRUST_PROXY=1` when behind a reverse proxy to honor secure cookies
- `BCRYPT_ROUNDS` (8-14; default 12)
- `REQUIRE_EMAIL_VERIFICATION` (`0` default, set `1` to require verified email for selected write actions)
- `DATABASE_URL` (PostgreSQL connection string)
- `ADMIN_USERNAME` (default `admin` for first-time bootstrap)
- `ADMIN_PASSWORD` (strongly recommended; used only when no admin exists yet)
- `ADMIN_EMAIL` (default `admin@example.local`)
- `ADMIN_RESET_ON_BOOT=1` to reset an existing super admin from `ADMIN_*` once

## Admin bootstrap
- On first start, if no admin exists, one is created.
- If `ADMIN_USERNAME` and `ADMIN_PASSWORD` are set, those are used; otherwise a random password is generated (hidden in production logs).
- Recovery: set `ADMIN_RESET_ON_BOOT=1` with `ADMIN_PASSWORD` (and optionally `ADMIN_USERNAME`/`ADMIN_EMAIL`), deploy once, log in, then clear `ADMIN_RESET_ON_BOOT`.

## Data and storage
- PostgreSQL tables: users, posts, comments, reactions, notifications
- Admin posts store `author_id` to distinguish admin content
- No email delivery or file uploads
- Data persists in your PostgreSQL instance; Supabase free tier works fine

## Security notes
- Passwords hashed with bcrypt; legacy SHA-256 hashes migrate on successful login.
- CSRF protection via per-session token and client helper in `public/csrf.js`.
- Cookies are httpOnly, SameSite=strict; `secure` when `NODE_ENV=production`.
- In-memory rate limiters on auth and write endpoints (reset on restart).
- Security headers: CSP, X-Frame-Options DENY, Referrer-Policy same-origin, X-Content-Type-Options nosniff, HSTS in production.
- Admin delete/flag actions are logged to stdout for audit visibility.

## Intentional limitations
- No email verification, password reset, or MFA.
- No media storage/uploads; posts are text-only.
- No WYSIWYG editor; body is plain text.
- No search indexing beyond simple SQL `LIKE`.
- Single-instance design; no horizontal scaling and rate limits are in-memory.

## Deploying or selling
- Ship the source; buyer runs `npm install && SESSION_SECRET=... DATABASE_URL=... node server.js`.
- Always set a strong `SESSION_SECRET`; run behind HTTPS and set `TRUST_PROXY=1` if fronted by a proxy.
- PostgreSQL keeps data across restarts; back it up for production use.

## Support
Offered as-is. For production, add backups, logging, HTTPS termination, and stronger monitoring/rate limiting as needed.

## Contributing
- Fork, create a feature branch, and keep changes scoped and reviewable.
- Install deps with `npm install`, set a local `DATABASE_URL`, and run `npm start` to verify behavior.
- Include repro steps in PR descriptions; avoid committing secrets or real credentials.
- Prefer small PRs that touch minimal files; add brief comments only where logic is non-obvious.

## Troubleshooting
- Server will not start: confirm `DATABASE_URL` is set and reachable; ensure `PORT` is free.
- Session/cookie issues behind a proxy: set `TRUST_PROXY=1` and ensure `SESSION_SECRET` is 16+ chars.
- CSRF errors: make sure the client fetches the token via `public/csrf.js` and sends it with write requests.
- Rate-limited locally: restart the server to clear in-memory counters; avoid rapid repeat POSTs.
- Admin login trouble: if the bootstrap admin is unknown, set `ADMIN_RESET_ON_BOOT=1` with new `ADMIN_PASSWORD`, restart once, then unset it.

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

