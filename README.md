# PHYSICS EDUCATION GROUPS

A production-ready **student group registration and management system** for Physics Education.

Students register into Physics Education groups. Each group holds at most **10 members**. The first successful member of a new group automatically becomes the **Group Leader**. Administrators get a **live dashboard** (Server-Sent Events) to manage groups, members, and CSV exports.

---

## Table of contents

1. What the project does
2. Technologies used
3. Project structure
4. Local installation
5. MongoDB Atlas setup
6. Environment variables
7. Running locally
8. GitHub deployment
9. Render deployment
10. Testing checklist
11. Administrator login
12. Database structure
13. API endpoints
14. Security considerations
15. Troubleshooting

---

## 1. What the project does

- **Public registration** — a student submits `REG NO`, `FULL NAME`, `PHONE`, `GROUP NAME`.
- **Automatic group creation** — the first student to use a group name creates it and becomes the **Group Leader** (`isLeader: true`).
- **Capacity enforcement** — hard limit of **10 members per group**, enforced atomically on the server with `findOneAndUpdate` + `$lt` filters. Cannot be bypassed by concurrent requests.
- **Duplicate protection** — unique `REG NO` across the whole system (MongoDB unique index), unique normalized group name, unique device ID.
- **Member login** — `USERNAME = GROUP NAME`, `PASSWORD = REGISTRATION NUMBER`. A student can only see **their own group**; the server reads the group from the session, never from client input.
- **Admin dashboard** — live view of total members, groups, leaders, recent registrations, per-group capacity, and full CRUD on groups and members.
- **Live updates** — the admin dashboard receives new registrations over Server-Sent Events with no page refresh.
- **CSV export** — a sorted, Excel-friendly list of every member in every group.
- **Deployed on Render** with **MongoDB Atlas** as the cloud database.

---

## 2. Technologies used

| Layer | Technology |
|-------|------------|
| Runtime | Node.js ≥ 18.17 |
| Server | Express 4 |
| Database | MongoDB Atlas (replica set) |
| ODM | Mongoose 8 |
| Frontend | HTML5 + CSS3 + Vanilla JavaScript (no framework) |
| Security | Helmet, CORS, express-rate-limit, HTTP-only cookies, CSRF double-submit |
| Live updates | Server-Sent Events (SSE) |
| Hosting | Render |
| Source control | GitHub |

**Explicitly not used:** React, Next.js, Firebase, Supabase, PHP, MySQL.

---

## 3. Project structure
