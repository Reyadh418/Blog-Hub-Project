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
- Verification workflow includes user-submitted author verification requests with super-admin approve/reject review actions.
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
- `PASSWORD_SALT` (optional; legacy-only, used to validate old SHA-256 passwords during migration to bcrypt)
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
- Automated tests are not configured yet (`npm test` is currently a placeholder script).
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

## License
This project is licensed under the GNU Affero General Public License v3.0 (AGPLv3).
See the `LICENSE` file for full terms.

## Visuals
**Home Page**
<img width="1898" height="877" alt="Screenshot 2026-03-04 010652" src="https://github.com/user-attachments/assets/75786c7b-cbb8-4ece-acfc-f1538543fe81" />

<img width="1897" height="882" alt="Screenshot 2026-03-04 010721" src="https://github.com/user-attachments/assets/9a25837f-207e-4af9-864e-03e5038f91a7" />

<img width="1897" height="878" alt="Screenshot 2026-03-04 010735" src="https://github.com/user-attachments/assets/5b800d39-418c-4d09-8565-c9b49e250f7c" />

**Not logged in**
<img width="1344" height="625" alt="Screenshot 2026-03-04 013201" src="https://github.com/user-attachments/assets/32e34645-960e-4b38-a1d8-824e9e9eb8f2" />

**Logged in as User**
<img width="1899" height="883" alt="Screenshot 2026-03-04 010758" src="https://github.com/user-attachments/assets/064e211d-5bc9-49ab-ab79-86950d7dab8e" />

**Logged in as Promoted Admin**
<img width="1348" height="616" alt="Screenshot 2026-03-04 012025" src="https://github.com/user-attachments/assets/93c756c8-e105-44a9-88f0-92d1ea2bd15c" />

**Logged in as Super Admin**
<img width="1344" height="632" alt="Screenshot 2026-03-04 021123" src="https://github.com/user-attachments/assets/3194a2c7-884b-4671-86e1-fc1eb85d56b2" />

**Search posts/stories**
<img width="1344" height="625" alt="Screenshot 2026-03-04 013201" src="https://github.com/user-attachments/assets/5408176e-06fa-447c-b9cc-96ec04988c2f" />

<img width="1350" height="628" alt="Screenshot 2026-03-04 012457" src="https://github.com/user-attachments/assets/8279d696-6544-40fa-9016-5a30985d0393" />

<img width="1347" height="629" alt="Screenshot 2026-03-04 012533" src="https://github.com/user-attachments/assets/02a0b1ba-09f7-4496-af63-fbd48f65eb8e" />

**Sort posts/stories**
<img width="1348" height="616" alt="Screenshot 2026-03-04 012025" src="https://github.com/user-attachments/assets/1e0580d2-5f26-48d2-82a7-f87e27fd4e62" />

<img width="1339" height="631" alt="Screenshot 2026-03-04 012601" src="https://github.com/user-attachments/assets/a7e4469c-c46d-45e8-8778-cf19a6eef6a2" />

<img width="1349" height="629" alt="Screenshot 2026-03-04 012610" src="https://github.com/user-attachments/assets/dc94f4ce-8a20-439e-a4b5-b25dd0237082" />

**Posts/Stories**
<img width="1349" height="631" alt="Screenshot 2026-03-04 021327" src="https://github.com/user-attachments/assets/e9245018-7b47-41ab-a64e-2afea459724b" />

<img width="1901" height="880" alt="Screenshot 2026-03-04 010812" src="https://github.com/user-attachments/assets/31fa15c4-c902-46ae-b47d-860a500aea94" />

**Register a new account**
<img width="1349" height="640" alt="Screenshot 2026-03-04 013230" src="https://github.com/user-attachments/assets/eadc67ca-0c2e-4aa7-9e93-76401a16a076" />

**Login to existing account**
<img width="1364" height="635" alt="Screenshot 2026-03-04 013250" src="https://github.com/user-attachments/assets/b0ea16e3-a268-4a6d-8a71-5914b4e604fb" />

**Email verification**
<img width="1344" height="634" alt="image" src="https://github.com/user-attachments/assets/e68ce5d0-c2c1-4478-bf6b-148182a6e174" />

**Profile Button(No unread notification)**
<img width="1899" height="878" alt="Screenshot 2026-03-04 010843" src="https://github.com/user-attachments/assets/5364ffca-bcd9-4a83-80ad-551abff9d9e7" />

**Profile Button(Unread Notification)**
<img width="1339" height="631" alt="Screenshot 2026-03-04 012601" src="https://github.com/user-attachments/assets/5fa7cf3c-ca17-4a87-bbfc-45846fd83511" />

<img width="1333" height="637" alt="Screenshot 2026-03-04 011653" src="https://github.com/user-attachments/assets/eddd1082-3ff2-4422-9237-0dd7d39fd2da" />

**Inside Notifications**
<img width="1342" height="630" alt="Screenshot 2026-03-04 011702" src="https://github.com/user-attachments/assets/9af3876e-68b0-4012-959a-096a8268dd1c" />

**User/Author Profile**
<img width="1896" height="878" alt="image" src="https://github.com/user-attachments/assets/01546441-7d52-4ecb-b9e0-ef1ba1f46eaa" />

<img width="1897" height="877" alt="Screenshot 2026-03-04 010926" src="https://github.com/user-attachments/assets/a76a5546-ff37-4928-a18b-ae5d0e825bd8" />

<img width="1898" height="881" alt="Screenshot 2026-03-04 010939" src="https://github.com/user-attachments/assets/3d159abb-6706-49a1-b60d-f4c17e5f18ed" />

**Promoted Admin Profile**
<img width="1348" height="631" alt="image" src="https://github.com/user-attachments/assets/ed32b2c3-b291-48de-93b5-29153271f2a5" />

<img width="1349" height="629" alt="Screenshot 2026-03-04 011733" src="https://github.com/user-attachments/assets/64a570fa-c170-4743-bd33-52eaf9af88df" />

<img width="1348" height="630" alt="Screenshot 2026-03-04 011747" src="https://github.com/user-attachments/assets/df576749-2927-4145-8d90-56a2c91d2f18" />

<img width="1347" height="629" alt="image" src="https://github.com/user-attachments/assets/70f00adb-7d60-48e4-a3ac-825904a7cd01" />

<img width="1350" height="633" alt="Screenshot 2026-03-04 011820" src="https://github.com/user-attachments/assets/44fcdf76-3250-4c57-98d7-91be524da42a" />

**Super Admin Profile**
<img width="1349" height="630" alt="Screenshot 2026-03-04 012710" src="https://github.com/user-attachments/assets/123dc970-52c8-433a-8cf4-ceac0a8995ff" />

<img width="1348" height="628" alt="Screenshot 2026-03-04 012722" src="https://github.com/user-attachments/assets/41055da6-df8e-46a3-a18b-c54f7b13ccd0" />

<img width="1346" height="634" alt="image" src="https://github.com/user-attachments/assets/9a07b914-d4bc-4458-be4b-760b095cabbf" />

<img width="1349" height="628" alt="Screenshot 2026-03-04 012923" src="https://github.com/user-attachments/assets/fbce41c1-d884-4ec5-8764-b9bb707e9e0f" />

<img width="1347" height="631" alt="Screenshot 2026-03-04 013037" src="https://github.com/user-attachments/assets/05291ec4-bb91-49ba-b4ee-98c1d803877f" />

<img width="1346" height="630" alt="Screenshot 2026-03-04 013131" src="https://github.com/user-attachments/assets/3c46061c-a116-4d40-a8d8-069667c62f35" />

**Create post/stories**
<img width="1345" height="633" alt="Screenshot 2026-03-04 011207" src="https://github.com/user-attachments/assets/7c4e398f-344f-4012-b18f-8584ff36b957" />

<img width="1347" height="640" alt="Screenshot 2026-03-04 011232" src="https://github.com/user-attachments/assets/d72f197e-a48d-48a8-bd4a-f72f64e65321" />

**Per post/story(Not Flagged)**
<img width="1349" height="641" alt="Screenshot 2026-03-04 022019" src="https://github.com/user-attachments/assets/1bd74585-597e-4b64-9a6d-f4c65af24ee0" />

**Per post/story(Flagged)**
<img width="1350" height="636" alt="Screenshot 2026-03-04 011304" src="https://github.com/user-attachments/assets/e5548c9b-b5c3-44f1-a816-46cfed5ab4d5" />

**Overflow Menu(Per post/story)**
<img width="1347" height="628" alt="Screenshot 2026-03-04 011520" src="https://github.com/user-attachments/assets/abcae249-4cd8-4511-bdbd-37fc81ebead7" />

**Per post/story page(End of post/story)**
<img width="1350" height="634" alt="Screenshot 2026-03-04 011545" src="https://github.com/user-attachments/assets/4435597c-740e-4c69-b738-efd3d4a0b3b3" />

**Reading mode**
<img width="1351" height="633" alt="Screenshot 2026-03-04 011559" src="https://github.com/user-attachments/assets/d4da09d3-743f-4c51-bb6a-fb21e2442720" />

<img width="1348" height="629" alt="Screenshot 2026-03-04 011608" src="https://github.com/user-attachments/assets/099cb7d7-d110-437b-a977-775191a4aa30" />

<img width="1347" height="634" alt="Screenshot 2026-03-04 011617" src="https://github.com/user-attachments/assets/852693be-7ae6-494b-9888-4fee27c0a112" />

**Comment(Single)**
<img width="1363" height="635" alt="Screenshot 2026-03-04 011327" src="https://github.com/user-attachments/assets/0ed24c1b-f003-4780-9943-36e1c7b229d4" />

**Comment(Nested)**
<img width="1344" height="630" alt="Screenshot 2026-03-04 011444" src="https://github.com/user-attachments/assets/b651258f-b3d8-4303-be3f-1883f5be646f" />

**Bookmark(Nothing saved)**
<img width="1356" height="633" alt="Screenshot 2026-03-04 011932" src="https://github.com/user-attachments/assets/46775a55-637b-438a-9e9b-9efec165be85" />

**Bookmark(Saved post/stories)**
<img width="1361" height="637" alt="Screenshot 2026-03-04 012006" src="https://github.com/user-attachments/assets/f66f71be-e8b8-480d-875e-f8b203271e1f" />

**Admin Management(Only Promoted Admin and Super Admin)**
<img width="1344" height="630" alt="Screenshot 2026-03-04 011838" src="https://github.com/user-attachments/assets/2e64fe0a-0812-43b4-a139-d60db0dea2f4" />

<img width="1345" height="632" alt="image" src="https://github.com/user-attachments/assets/506aaaee-a753-4972-9beb-2e4e13bb9eda" />

<img width="1347" height="629" alt="Screenshot 2026-03-04 011859" src="https://github.com/user-attachments/assets/711cc92a-2715-4f69-a95d-797b2f18707d" />

**User list(Only Super Admin)**
<img width="1362" height="630" alt="image" src="https://github.com/user-attachments/assets/234bb197-16e2-48ed-aaf9-a60256744d5b" />

**Profile Information(Only Super Admin)**
<img width="1348" height="630" alt="image" src="https://github.com/user-attachments/assets/c6e49742-a2d2-4f0d-9f18-a5826de6be92" />

<img width="1348" height="628" alt="Screenshot 2026-03-04 013006" src="https://github.com/user-attachments/assets/e0b0262c-64b7-4737-9b85-bf72d07dff87" />

**Edit Profile(User + Promoted Admin)**
<img width="1900" height="882" alt="image" src="https://github.com/user-attachments/assets/d3c0d38b-596d-47f7-9a0f-af0edc5c17ea" />

<img width="1898" height="881" alt="Screenshot 2026-03-04 011031" src="https://github.com/user-attachments/assets/e7875dea-184f-4bdc-afe1-db27e950461a" />

<img width="1346" height="636" alt="Screenshot 2026-03-04 011143" src="https://github.com/user-attachments/assets/55f12653-4334-4ae4-9d9e-2625f0c7f5c5" />

**Edit Profile(Super Admin)**
<img width="1348" height="630" alt="Screenshot 2026-03-04 012739" src="https://github.com/user-attachments/assets/d9c30749-9993-4841-95c6-065149ef6721" />

<img width="1348" height="640" alt="Screenshot 2026-03-04 012755" src="https://github.com/user-attachments/assets/620ea789-ed21-4ab7-bcfe-d9a99f97d252" />

**Author verification by Admin**
<img width="1347" height="629" alt="image" src="https://github.com/user-attachments/assets/70f00adb-7d60-48e4-a3ac-825904a7cd01" />
