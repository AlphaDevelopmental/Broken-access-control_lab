# 🔐 Broken Access Control Lab
### A CTF-style pentesting lab for OWASP A01:2021

> **Target audience:** Security students who know Express/Node and want hands-on  
> experience finding and fixing real access control vulnerabilities.

---

## What You'll Learn

By the end of this lab you will be able to:

- Identify and exploit **Insecure Direct Object References (IDOR)**
- Exploit **vertical privilege escalation** caused by missing or misconfigured middleware
- Forge **JWT tokens** using algorithm confusion (`alg:none`) and weak secret cracking
- **Fix** each vulnerability using correct patterns — not just identify them
- Reason about the difference between authentication, authorization, and ownership

---

## The App

You're pentesting **ExpenseTracker API** — a fictional internal tool for submitting
and approving employee expenses. It has four user roles:

| Username | Password | Role | Can do |
|---|---|---|---|
| `alice` | `password123` | `user` | Manage her own expenses |
| `bob` | `password123` | `user` | Manage his own expenses |
| `carol` | `password123` | `manager` | Read/approve all expenses |
| `admin` | `adminpass` | `admin` | Full access + user management |

The app looks secure at first glance. It has a JWT login system, a centralized
permissions map, and access control middleware. But 8 bugs are hiding in the code.

---

## Setup

**Prerequisites:** Node.js 18+, npm

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/broken-access-control-lab
cd broken-access-control-lab

# Install dependencies
npm install

# Start the server
npm start
# → Running on http://localhost:3000

# In a separate terminal, run all tests
npm test

# Or run one exercise at a time
npm run test:01
npm run test:02
npm run test:03
```

---

## How Auth Works

All protected routes require a JWT in the `Authorization` header:

```bash
# Step 1: Login and get your token
curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}'

# Response:
# {
#   "token": "eyJhbGciOiJIUzI1NiJ9...",
#   "user": { "id": 1, "username": "alice", "role": "user" }
# }

# Step 2: Use the token
curl -s http://localhost:3000/api/expenses/1 \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9..."
```

Switch roles by logging in as different users. Each user's token encodes their role
in the JWT payload — that's also one of the things you'll attack in Exercise 03.

---

## The Vulnerability Map

The lab contains **8 intentional vulnerabilities** across 3 exercises.
**Do not read this table until you've attempted each exercise** — it spoils the hunt.

<details>
<summary>⚠️ Spoiler — click to reveal the full bug map</summary>

| # | Type | Route | Bug | Flag |
|---|---|---|---|---|
| 1 | IDOR Read | `GET /api/expenses/:id` | `requireOwnership()` not applied | `BAC{idor_read_unlocked}` |
| 2 | IDOR Write | `PUT /api/expenses/:id` | `requireOwnership()` not applied | `BAC{idor_write_unlocked}` |
| 3 | IDOR Delete | `DELETE /api/expenses/:id` | `requireOwnership()` not applied | *(combined with #5)* |
| 4 | Vertical | `GET /api/admin/users` | `requirePermission()` missing entirely | `BAC{vertical_escalation_no_permission_check}` |
| 5 | Vertical | `DELETE /api/expenses/:id` | Wrong permission string (`read` instead of `delete_own`) | `BAC{idor_delete_and_vertical_unlocked}` |
| 6 | Vertical | `POST /api/expenses/approve/:id` | Manual role check blocks legitimate managers | `BAC{manual_role_check_bypasses_permission_system}` |
| 7 | JWT | `verifyToken()` in `auth.js` | `alg:none` tokens accepted (no algorithm whitelist) | `BAC{jwt_alg_none_accepted}` |
| 8 | JWT | `JWT_SECRET` in `auth.js` | Hardcoded weak secret (`"secret"`) | `BAC{jwt_weak_secret_cracked}` |

</details>

---

## Exercise Structure

Each exercise follows the same two-phase rhythm:

### Phase 1: Exploit
Run the 🔴 exploit tests — they **pass** when the vulnerability exists.
Use `curl` or the automated tests to confirm the bug fires and capture the flag.

### Phase 2: Harden
Fix the code. The 🔴 exploit tests should now **fail** (the bug is gone).
The 🟢 hardening tests should now **pass** (your fix is verified).

```
Before fix:   🔴 EXPLOIT → PASS  |  🟢 HARDENING → FAIL
After fix:    🔴 EXPLOIT → FAIL  |  🟢 HARDENING → PASS
```

---

## Exercises

### [Exercise 01 — IDOR](./exercises/01-idor/challenge.md)
Horizontal privilege escalation. Alice reads, modifies, and deletes Bob's expenses
using only her own valid session. The ownership check is absent.

```bash
npm run test:01
```

---

### [Exercise 02 — Vertical Escalation](./exercises/02-escalation/challenge.md)
A `user`-role token reaches admin and manager functions. Three separate bugs:
a missing middleware call, a wrong permission string, and a manual role check
that bypasses the permission registry.

```bash
npm run test:02
```

---

### [Exercise 03 — JWT Abuse](./exercises/03-jwt-abuse/challenge.md)
The middleware is now correctly applied — but the tokens themselves are forgeable.
Exploit algorithm confusion (`alg:none`) and a weak signing secret to forge
an admin JWT without knowing the password.

```bash
npm run test:03
```

---

## Scoring

Collect all 8 flags:

| Flag | Exercise | Points |
|---|---|---|
| `BAC{idor_read_unlocked}` | 01 | 10 |
| `BAC{idor_write_unlocked}` | 01 | 10 |
| `BAC{idor_delete_and_vertical_unlocked}` | 01 / 02 | 15 |
| `BAC{vertical_escalation_no_permission_check}` | 02 | 10 |
| `BAC{manual_role_check_bypasses_permission_system}` | 02 | 15 |
| `BAC{jwt_alg_none_accepted}` | 03 | 20 |
| `BAC{jwt_weak_secret_cracked}` | 03 | 20 |
| All hardening tests green | All | **+50 bonus** |
| **Total** | | **150** |

---

## Project Structure

```
broken-access-control-lab/
├── src/
│   ├── auth.js         # JWT login + verifyToken middleware  [Bugs #7, #8]
│   ├── roles.js        # Centralized PERMISSIONS map (source of truth)
│   ├── middleware.js   # requirePermission + requireOwnership factories
│   ├── data.js         # In-memory "database": users + expenses
│   └── app.js          # Express routes                     [Bugs #1-#6]
├── exercises/
│   ├── 01-idor/
│   │   ├── challenge.md       # Mission briefing + curl commands
│   │   └── idor.test.js       # Jest test suite
│   ├── 02-escalation/
│   │   ├── challenge.md
│   │   └── escalation.test.js
│   └── 03-jwt-abuse/
│       ├── challenge.md
│       └── jwt-abuse.test.js
├── package.json
└── README.md
```

---

## Solutions

Solutions are maintained in a **private repository** — contact the lab author
for instructor access. This keeps the exploit/fix experience intact for students.

---

## Key Concepts Reference

### The Three Access Control Questions

Every protected route should answer all three:

1. **Authentication:** Is this user logged in? (`verifyToken`)
2. **Authorization:** Does their role allow this action? (`requirePermission`)
3. **Ownership:** Do they own this specific resource? (`requireOwnership`)

Missing any one of them is a vulnerability.

---

### The Permission Hierarchy

```
src/roles.js  ←  single source of truth
      ↓
src/middleware.js → requirePermission('expenses:read_own')
      ↓
src/app.js → applied to routes
```

Never write `if (req.user.role === 'admin')` inline. Always go through
`requirePermission()`. The middleware is the contract.

---

### JWT Security Checklist

- [ ] Whitelist allowed algorithms: `{ algorithms: ['HS256'] }`
- [ ] Use a strong secret: 256-bit random, from environment variable
- [ ] Set a short expiry: `{ expiresIn: '15m' }` or `'2h'` max
- [ ] Rotate secrets periodically and on suspected compromise
- [ ] Never put sensitive data in the JWT payload (it's base64, not encrypted)

---

## Further Reading

- [OWASP A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [PortSwigger Web Security Academy – Access Control](https://portswigger.net/web-security/access-control)
- [PortSwigger – JWT Attacks](https://portswigger.net/web-security/jwt)
- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [jwt.io](https://jwt.io) — JWT debugger

---

## License

MIT — fork it, adapt it, use it in your courses.
