# Exercise 02 — Broken Access Control: Vertical Privilege Escalation
## Accessing Higher-Privilege Functions Without the Required Role

> **Difficulty:** ⭐⭐⭐☆☆  
> **Flags to capture:** 3  
> **OWASP Category:** [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
> **Prerequisite:** Complete Exercise 01 first (or at least understand IDOR).

---

## Your Mission

Same app, same credentials. But this time you're not going sideways —
you're going **up**.

You're logged in as **alice / password123** (role: `user`).  
The `user` role has very limited permissions (see `src/roles.js`).

But the routes don't always enforce those limits correctly.
Three routes have broken access control at the *vertical* level —
meaning a `user`-role token can reach functionality reserved for
`manager` or `admin` roles.

Find them. Exploit them. Fix them.

---

## Background: Vertical vs Horizontal Escalation

| Type | Who you are | What you're accessing |
|---|---|---|
| **Horizontal** (Ex 01) | Alice (user) | Bob's resources (same role) |
| **Vertical** (Ex 02) | Alice (user) | Admin/manager functions (higher role) |

Both are broken access control. Vertical escalation is often more dangerous —
you're not just reading someone else's data, you're reaching functions that
could affect the entire system.

---

## Phase 1: Recon

Start the server: `npm start`

Get Alice's token:
```bash
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | jq -r .token)

echo "Alice's role: user"
echo "Token: $TOKEN"
```

Now audit every route. Ask for each one:
1. What permission does the PERMISSIONS map say is required?
2. What does the route actually check?
3. Is there a gap?

Routes to probe:
```bash
# Should require 'users:read' (admin only) — does it?
curl -s http://localhost:3000/api/admin/users \
  -H "Authorization: Bearer $TOKEN" | jq .

# Should require 'expenses:delete_own' — what does it actually check?
curl -s -X DELETE http://localhost:3000/api/expenses/7 \
  -H "Authorization: Bearer $TOKEN" | jq .

# Should allow manager to approve — can they?
CAROL_TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"carol","password":"password123"}' | jq -r .token)

curl -s -X POST http://localhost:3000/api/expenses/approve/6 \
  -H "Authorization: Bearer $CAROL_TOKEN" | jq .
```

---

## Phase 2: Exploit

### Bug #4 — Missing Guard on Admin Route

```bash
# Alice (role: user) should NOT be able to list all users
curl -s http://localhost:3000/api/admin/users \
  -H "Authorization: Bearer $TOKEN" | jq .
```
Expected (before fix): **200 OK** with full user list + flag  
Expected (after fix): **403 Forbidden**

---

### Bug #5 — Wrong Permission String on Delete Route

Open `src/app.js` and find `DELETE /api/expenses/:id`.

What permission string is being checked? Now check `src/roles.js`.
Does the `user` role have that permission? Should it?

```bash
# Alice deletes an expense she shouldn't be able to delete at all
curl -s -X DELETE http://localhost:3000/api/expenses/7 \
  -H "Authorization: Bearer $TOKEN" | jq .
```
Expected (before fix): **200 OK** — Alice deletes Carol's expense  
Expected (after fix): **403 Forbidden**

---

### Bug #6 — Manual Role Check Blocks Legitimate Users + Wrong Logic

Try approving an expense as Carol (manager role):
```bash
curl -s -X POST http://localhost:3000/api/expenses/approve/6 \
  -H "Authorization: Bearer $CAROL_TOKEN" | jq .
```

Expected (before fix): **403 Forbidden** — but the flag in the error body  
reveals *why* this is wrong. Carol *should* be able to approve.

The code has a manual `if (req.user.role !== 'admin')` check instead of
using `requirePermission('expenses:approve')`. This:
- Blocks managers (who should be allowed per `PERMISSIONS`)
- Bypasses the centralized permission registry entirely

---

## Phase 3: Root Cause Analysis

For each bug, locate the exact line in `src/app.js` and answer:

**Bug #4:**
- Which middleware call is entirely missing from this route?

**Bug #5:**
- What string is passed to `requirePermission()`?
- What string *should* be passed? (Check `src/roles.js`)

**Bug #6:**
- What check exists instead of `requirePermission()`?
- Why is a manual `role` check worse than using the permission system?
- What permission string should replace it?

---

## Phase 4: Patch

### Fix Bug #4
In `src/app.js`, uncomment the `requirePermission` call on `GET /api/admin/users`:
```javascript
app.get('/api/admin/users',
  verifyToken,
  requirePermission('users:read'),  // ← uncomment this
  handler
)
```

### Fix Bug #5
Change the permission string on `DELETE /api/expenses/:id`:
```javascript
// Before:
requirePermission('expenses:read')

// After:
requirePermission('expenses:delete_own')
```

### Fix Bug #6
Replace the inline role check with the middleware:
```javascript
// Before (inline manual check):
(req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403)...
  next()
}

// After:
requirePermission('expenses:approve')
```

After fixing Bug #6, verify that Carol (manager) can now approve expenses.

---

## Phase 5: Verify

```bash
npm run test:02
```

All 🟢 HARDENING tests green = Exercise 02 complete.

---

## Flags

| # | Flag | Route |
|---|---|---|
| 4 | `BAC{vertical_escalation_no_permission_check}` | `GET /api/admin/users` |
| 5 | `BAC{idor_delete_and_vertical_unlocked}` | `DELETE /api/expenses/:id` |
| 6 | `BAC{manual_role_check_bypasses_permission_system}` | `POST /api/expenses/approve/:id` |

---

## Further Reading

- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [PortSwigger: Vertical Privilege Escalation](https://portswigger.net/web-security/access-control#vertical-privilege-escalation)
- [OWASP Testing Guide: Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)
