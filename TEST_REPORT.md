# Broken Access Control Lab - Test Report

**Generated:** April 20, 2026  
**Status:** Pre-fix baseline (vulnerabilities should be present)

---

## Summary

- **Total Tests:** 42
- **Passed:** 30 ✓
- **Failed:** 12 ✗

---

## Exercise 01 - IDOR (Insecure Direct Object References)

### Bug #1: IDOR Read (GET /api/expenses/:id)
- **Status:** ✓ Vulnerable (exploit test passes)
- **Exploit (🔴):**  ✓ PASS - Alice can read Bob's expense
- **Hardening (🟢):** ✗ FAIL - Alice still reads Bob's expense (expects 403, got 200)
- **Assessment:** `requireOwnership()` middleware is not applied to the GET route
- **Fix Needed:** Add `requireOwnership()` after `requirePermission()`

### Bug #2: IDOR Write (PUT /api/expenses/:id)
- **Status:** ✓ Vulnerable (exploit test passes)
- **Exploit (🔴):** ✓ PASS - Alice can modify Bob's expense
- **Hardening (🟢):** ✗ FAIL - Alice still modifies Bob's expense (expects 403, got 200)
- **Assessment:** `requireOwnership()` middleware is not applied to the PUT route
- **Fix Needed:** Add `requireOwnership()` after `requirePermission()`

### Bug #3: IDOR Delete (DELETE /api/expenses/:id)
- **Status:** ⚠️ Partially Broken
- **Exploit (🔴):** ✗ FAIL - Alice cannot delete Bob's expense (expects 200, got 403)
- **Hardening (🟢):** ✗ FAIL - Alice cannot delete her own expense (expects 200, got 403)
- **Assessment:** Issue with Bug #5 interference - the DELETE endpoint checks wrong permission
- **Root Cause:** Bug #5 (wrong permission 'expenses:read') prevents users from any deletion

---

## Exercise 02 - Vertical Privilege Escalation

### Bug #4: No Permission Check on Admin Route (GET /api/admin/users)
- **Status:** ✓ Vulnerable (no permission middleware applied)
- **Exploit (🔴):** ✓ PASS - User role can access admin user list
- **Hardening (🟢):** ✗ FAIL - User still accesses admin list (expects 403, got 200)
- **Assessment:** `requirePermission('users:read')` middleware is missing
- **Fix Needed:** Add `requirePermission('users:read')` after `verifyToken`

### Bug #5: Wrong Permission String on DELETE Route
- **Status:** ⚠️ Test Issue (permission model mismatch)
- **Exploit (🔴):** ✗ FAIL - User cannot delete (expects 200, got 403)
- **Hardening (🟢):** ✓ PASS - User denied delete on others' expenses
- **Root Cause:** Current code checks `'expenses:read'` which user doesn't have
- **Issue:** Test comment says "user HAS 'expenses:read'" but actually user doesn't
- **Assessment:** The permission model may need adjustment or test expectation is wrong

### Bug #6: Manual Role Check Bypasses Permission System
- **Status:** ✓ Vulnerable (manual check blocks managers)
- **Exploit (🔴):** ✓ PASS - Manager is incorrectly denied approve access
- **Hardening (🟢):** ✗ FAIL - Manager/Admin still blocked (expects 200, got 403/404)
- **Assessment:** Code uses `if (req.user.role !== 'admin')` instead of `requirePermission()`
- **Fix Needed:** Replace manual check with `requirePermission('expenses:approve')`

---

## Exercise 03 - JWT Abuse

### Bug #7: JWT Algorithm Confusion (alg:none accepted)
- **Status:** ✓ Vulnerable (unsigned tokens accepted)
- **Exploit (🔴):** ✓ PASS - alg:none token with admin payload accepted
- **Hardening (🟢):** ✗ FAIL - alg:none token still accepted (expects 401, got 200)
- **Assessment:** `verifyToken()` manually accepts unsigned tokens
- **Fix Needed:** Remove `{ algorithms: ['HS256', 'none'] }` and restrict to `{ algorithms: ['HS256'] }`

### Bug #8: Weak JWT Secret (hardcoded "secret")
- **Status:** ✓ Vulnerable (weak secret crackable)
- **Exploit (🔴):** ✓ PASS - Secret "secret" cracked easily, admin token forged
- **Hardening (🟢):** ✗ FAIL - Secret still "secret" 6 chars (expects ≥32)
- **Assessment:** `JWT_SECRET` is hardcoded weak value in src/auth.js
- **Fix Needed:** Read strong secret from .env file with >= 32 random characters

---

## Test Result Summary Table

| Bug # | Exercise | Exploit | Hardening | Status | Priority |
|-------|----------|---------|-----------|--------|----------|
| #1 | 01 | ✓ PASS | ✗ FAIL | Vulnerable | HIGH |
| #2 | 01 | ✓ PASS | ✗ FAIL | Vulnerable | HIGH |
| #3 | 01 | ✗ FAIL | ✗ FAIL | Blocked by #5 | MEDIUM |
| #4 | 02 | ✓ PASS | ✗ FAIL | Vulnerable | HIGH |
| #5 | 02 | ✗ FAIL | ✓ PASS | Test Issue | MEDIUM |
| #6 | 02 | ✓ PASS | ✗ FAIL | Vulnerable | HIGH |
| #7 | 03 | ✓ PASS | ✗ FAIL | Vulnerable | HIGH |
| #8 | 03 | ✓ PASS | ✗ FAIL | Vulnerable | HIGH |

---

## Critical Issues to Address

1. **Bug #5 Test Mismatch:** The exploit test expects something that's not possible given the current role permissions
   - Test comment says user has 'expenses:read' but they don't
   - Either fix role permissions or fix test expectations

2. **JWT Secret Exposure:** Current code hardcodes weak secret
   - Should read from environment variable
   - Needs to be >= 32 characters for hardening test to pass

3. **Middleware Application:** Several middlewares need to be applied to routes
   - `requireOwnership()` on GET/PUT/DELETE expenses
   - `requirePermission('users:read')` on GET /api/admin/users
   - `requirePermission('expenses:approve')` on POST /api/expenses/approve/:id

---

## File Status

| File | Issues | Status |
|------|--------|--------|
| src/data.js | ✓ Fixed | Password hashes corrected |
| src/auth.js | ⚠️ Bug #7, #8 Present | Vulnerable as intended (alg:none accepted, weak secret) |
| src/app.js | ⚠️ Bugs #1-6 Present | Vulnerable as intended (missing middleware, wrong perms) |
| exercises/02-escalation/escalation.test.js | ⚠️ Bug #5 Test Issue | Exploit test expectations don't match role model |
| package.json | ✓ Fixed | jsonwebtoken downgraded to 8.5.1 |

