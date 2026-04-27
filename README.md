# 🔐 Broken Access Control Lab
### A CTF-style pentesting lab for OWASP A01:2021

**Keywords:** security, penetration testing, OWASP, access control, IDOR, JWT, privilege escalation, authentication, authorization, CTF, Express.js, Node.js, curl, jq, hands-on learning

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

## Setup & Prerequisites

### Required Tools

| Tool | Version | Used For |
|------|---------|----------|
| **Node.js** | 18+ | Running the server & tests |
| **npm** | Latest | Package management |
| **curl** | Any | Making HTTP requests, exploiting vulnerabilities |
| **jq** | Any | Parsing JSON responses |
| **bash/zsh** | Any | Shell scripting for exploits |
| **Text Editor** | Any | Reading & fixing code |

### Installation

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
npm run test:04
npm run test:05
```

### Tools Installation (if needed)

**macOS:**
```bash
brew install curl jq
```

**Ubuntu/Debian:**
```bash
sudo apt-get install curl jq
```

**Windows (WSL2):**
```bash
apt-get install curl jq
```

Most systems have `curl` and basic shells pre-installed. `jq` is the only tool you might need to install explicitly.

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

## Typical Workflow

Here's how you'll use these tools for each exercise:

```bash
# Terminal 1: Start the server
npm start

# Terminal 2: Get a JWT token (curl + jq)
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | jq -r .token)

# Terminal 2: Exploit the vulnerability (curl + jq)
curl -s http://localhost:3000/api/expenses/4 \
  -H "Authorization: Bearer $TOKEN" | jq .

# Terminal 2: Decode JWT payload (node)
node -e "
  const parts = '$TOKEN'.split('.');
  console.log(JSON.parse(Buffer.from(parts[1], 'base64url').toString()));
"

# Terminal 2 or Editor: Fix the code
vim src/app.js
# or: code src/app.js

# Terminal 2: Verify your fix
npm run test:01
```

**Key tools in action:**
- **curl** — sends HTTP requests to the API
- **jq** — parses JSON responses and extracts specific fields
- **node** — crafts and decodes JWT tokens
- **npm** — runs server and tests
- **Editor** — read and fix vulnerable code

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
| 9 | Attribute-Based | `GET /api/expenses/search` | No ownership filter on search results | `BAC{search_no_ownership_filter}` |
| 10 | Batch Operation | `POST /api/expenses/bulk-update` | No per-item ownership checks | `BAC{bulk_update_no_item_checks}` |
| 11 | Batch Operation | `DELETE /api/expenses/category/:cat` | No per-item ownership checks | `BAC{bulk_delete_no_item_checks}` |
| 12 | Multi-Tenant | `GET /api/expenses` | Org context from header, not re-validated | `BAC{cross_org_no_context_validation}` |
| 13 | Multi-Tenant | `POST /api/org/setup` | First user auto-promoted, no re-validation | `BAC{org_setup_no_admin_validation}` |
| 14 | Multi-Tenant | `POST /api/org/invite` | No authorization check on invite | `BAC{org_invite_no_authorization}` |

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

### [Exercise 04 — Context/Attribute-Based Bypass](./exercises/04-context-bypass/challenge.md) ⭐ Advanced
Batch operations and search functions skip per-item authorization checks.
Find three routes that process multiple items but only validate permission once.
Exploit search filtering, bulk updates, and bulk deletes to access/modify other users' data.

```bash
npm run test:04
```

---

### [Exercise 05 — Multi-Tenant Isolation](./exercises/05-multitenant/challenge.md) ⭐ Expert
The app now supports multiple organizations. Exploit three multi-tenant vulnerabilities:
org context manipulation, first-user admin escalation, and unvalidated org invites.
Learn why user-controlled context is dangerous and how to properly validate it.

```bash
npm run test:05
```

---

## Scoring

Collect all 14 flags across 5 exercises:

| Flag | Exercise | Points |
|---|---|---|
| `BAC{idor_read_unlocked}` | 01 | 10 |
| `BAC{idor_write_unlocked}` | 01 | 10 |
| `BAC{idor_delete_and_vertical_unlocked}` | 01 / 02 | 15 |
| `BAC{vertical_escalation_no_permission_check}` | 02 | 10 |
| `BAC{manual_role_check_bypasses_permission_system}` | 02 | 15 |
| `BAC{jwt_alg_none_accepted}` | 03 | 20 |
| `BAC{jwt_weak_secret_cracked}` | 03 | 20 |
| `BAC{search_no_ownership_filter}` | 04 | 15 |
| `BAC{bulk_update_no_item_checks}` | 04 | 15 |
| `BAC{bulk_delete_no_item_checks}` | 04 | 15 |
| `BAC{cross_org_no_context_validation}` | 05 | 20 |
| `BAC{org_setup_no_admin_validation}` | 05 | 20 |
| `BAC{org_invite_no_authorization}` | 05 | 20 |
| All hardening tests green | All | **+50 bonus** |
| **Total** | | **245** |

---

## Project Structure

```
broken-access-control-lab/
├── src/
│   ├── auth.js         # JWT login + verifyToken middleware  [Bugs #7, #8]
│   ├── roles.js        # Centralized PERMISSIONS map (source of truth)
│   ├── middleware.js   # requirePermission + requireOwnership factories
│   ├── data.js         # In-memory "database": users + expenses
│   └── app.js          # Express routes                     [Bugs #1-#6, #9-#12]
├── exercises/
│   ├── 01-idor/
│   │   ├── challenge.md       # Mission briefing + curl commands
│   │   └── idor.test.js       # Jest test suite
│   ├── 02-escalation/
│   │   ├── challenge.md
│   │   └── escalation.test.js
│   ├── 03-jwt-abuse/
│   │   ├── challenge.md
│   │   └── jwt-abuse.test.js
│   ├── 04-context-bypass/
│   │   ├── challenge.md
│   │   └── context-bypass.test.js
│   └── 05-multitenant/
│       ├── challenge.md
│       └── multitenant.test.js
├── WALKTHROUGH.md      # Complete step-by-step guide for all exercises
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

## Credits & Tools Used

**This lab was created by:** [@AlphaDevelopmental](https://github.com/AlphaDevelopmental/)

### Tools & Technologies

This lab leverages the following open-source tools and technologies:

| Tool | Purpose | Reference |
|------|---------|-----------|
| **Node.js / npm** | Runtime & package management | https://nodejs.org |
| **Express.js** | Web framework | https://expressjs.com |
| **jsonwebtoken (jwt)** | JWT signing & verification | https://github.com/auth0/node-jsonwebtoken |
| **bcryptjs** | Password hashing | https://github.com/dcodeIO/bcrypt.js |
| **Jest** | Test framework | https://jestjs.io |
| **Supertest** | HTTP assertion library | https://github.com/visionmedia/supertest |
| **curl** | HTTP client | https://curl.se |
| **jq** | JSON processor | https://stedolan.github.io/jq |
| **Bash/Zsh** | Shell scripting | GNU Project |

### Inspired By

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)
- [DVWA (Damn Vulnerable Web Application)](http://www.dvwa.co.uk)
- [HackTheBox](https://www.hackthebox.com)
- [TryHackMe](https://tryhackme.com)

---

## License

MIT — fork it, adapt it, use it in your courses.
