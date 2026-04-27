# Exercise 04 — Broken Access Control: Context/Attribute-Based Bypass
## Exploiting Resource Attributes Instead of User Identity

> **Difficulty:** ⭐⭐⭐⭐☆  
> **Flags to capture:** 2  
> **OWASP Category:** [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)  
> **Prerequisites:** Exercises 01–03 should be conceptually understood (assumes bugs there are fixed).

---

## Your Mission

The app's role-based access control is now properly enforced: ownership checks are in place, permission middleware is applied correctly, and JWTs are properly validated.

But there's a new class of vulnerability: **attribute-based authorization bypass**.

Sometimes the server makes access decisions based not just on *who you are* (user ID, role), but on *what state the resource is in* (expense status, amount, category). If these checks are incomplete or can be manipulated, an attacker can bypass authorization.

Two new routes have been added to demonstrate this:

1. **Low-value expense bypass** — Users can approve/delete expenses below a certain threshold
2. **Bulk action bypass** — A batch operation doesn't properly validate each item

Your job: Find these bypasses, exploit them, and fix them.

---

## Background: Attribute-Based Access Control (ABAC)

| Type | Example |
|---|---|
| **RBAC** (Role-Based) | "Only admins can approve" |
| **ABAC** (Attribute-Based) | "Only admins can approve expenses over $500" |
| **Broken ABAC** | "Any manager can approve if amount < $100" (without actually checking the amount!) |

Many real-world apps use ABAC to allow more flexible policies. But if the attribute checks are incomplete or missing, they become a new attack surface.

---

## Phase 1: Recon

Start with Alice's token (role: user):

```bash
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | jq -r .token)

echo "Token: $TOKEN"
```

### New Routes to Audit

**Route A: GET /api/expenses/search**
```bash
# Query expense by category (should respect ownership)
curl -s "http://localhost:3000/api/expenses/search?category=travel" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**Route B: POST /api/expenses/bulk-update**
```bash
# Update multiple expenses at once (dangerous!)
curl -s -X POST http://localhost:3000/api/expenses/bulk-update \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ids":[1,2,3,4,5],"status":"approved"}' | jq .
```

**Route C: DELETE /api/expenses/category/:category**
```bash
# Delete all expenses in a category (should check ownership per item)
curl -s -X DELETE "http://localhost:3000/api/expenses/category/misc" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

---

## Phase 2: Exploit

### Bypass A: Search Doesn't Filter by Ownership

The `/api/expenses/search` endpoint accepts a `category` query parameter, but **doesn't check if you own the results**. You can enumerate all expenses in a category regardless of owner.

```bash
# Alice searches for "travel" and gets Bob's travel expenses too
curl -s "http://localhost:3000/api/expenses/search?category=travel" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

Expected (vulnerable): Full list of all travel expenses, including Bob's  
Expected (fixed): Only Alice's travel expenses

---

### Bypass B: Bulk Update Missing Per-Item Authorization

The `/api/expenses/bulk-update` endpoint accepts an array of expense IDs and a new status, but **checks the permission only once, then applies to all IDs without re-checking ownership**:

```javascript
// Vulnerable code pattern:
requirePermission('expenses:update_own');  // checked ONCE
const ids = req.body.ids;
ids.forEach(id => {
  updateExpense(id, req.body);  // NO ownership check per item!
});
```

```bash
# Alice updates Bob's expenses to "approved"
curl -s -X POST http://localhost:3000/api/expenses/bulk-update \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ids":[4,5],"status":"approved"}' | jq .
```

Expected (vulnerable): Both of Bob's expenses are approved  
Expected (fixed): 403 Forbidden or partial success with error details

---

### Bypass C: Bulk Delete by Category Doesn't Check Per-Item Ownership

Similar to Bypass B, the bulk delete route validates the permission but not ownership:

```bash
# Alice deletes all "misc" category expenses (including Bob's)
curl -s -X DELETE "http://localhost:3000/api/expenses/category/misc" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

---

## Phase 3: Root Cause Analysis

After exploiting, analyze the code:

1. **Open [src/app.js](src/app.js)** and find the three new routes
2. **Ask:** Does the route check ownership *per item*, or just the initial permission?
3. **Ask:** Is a query parameter (`category`, `filter`, `limit`) used to skip authorization on some items?

---

## Phase 4: Patching

### Fix A: Filter Results by Ownership

```javascript
// BEFORE (vulnerable):
const expenses = getAllExpensesByCategory(req.query.category);
res.json({ data: expenses });

// AFTER (fixed):
const expenses = getAllExpensesByCategory(req.query.category)
  .filter(exp => exp.ownerId === req.user.userId);
res.json({ data: expenses });
```

### Fix B & C: Validate Each Item in Bulk Operations

```javascript
// BEFORE (vulnerable):
requirePermission('expenses:update_own');
const ids = req.body.ids;
ids.forEach(id => updateExpense(id, req.body));

// AFTER (fixed):
requirePermission('expenses:update_own');
const ids = req.body.ids;
const results = [];
for (const id of ids) {
  const expense = findExpenseById(id);
  if (!expense) {
    results.push({ id, success: false, error: 'Not found' });
    continue;
  }
  if (expense.ownerId !== req.user.userId) {
    results.push({ id, success: false, error: 'Access Denied' });
    continue;
  }
  updateExpense(id, req.body);
  results.push({ id, success: true });
}
res.json({ results });
```

---

## Phase 5: Verification

Run the tests:

```bash
npm run test:04
```

Expected output:
- 🔴 **Exploit tests FAIL** (bugs are now fixed)
- 🟢 **Hardening tests PASS** (your patches work)

---

## Real-World Impact

This class of vulnerability affects:

- **Batch operations** — Email clients, ticketing systems, e-commerce carts
- **Search/filter** — File sharing, project management, social media
- **Bulk exports** — Analytics dashboards, reporting tools
- **Webhooks/automations** — Workflow systems that process multiple items

Always ask: *"Is this permission check applied to every item, or just once at the start?"*

