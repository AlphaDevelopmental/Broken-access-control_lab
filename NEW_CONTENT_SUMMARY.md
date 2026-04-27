# New Exercises & Walkthrough Summary

## What I Created

### ✨ Two New Exercises

#### **Exercise 04: Context/Attribute-Based Access Control Bypass**
- **Difficulty:** ⭐⭐⭐⭐☆ (Advanced)
- **Files Created:**
  - `/exercises/04-context-bypass/challenge.md` — Mission briefing
  - `/exercises/04-context-bypass/context-bypass.test.js` — Jest test suite
- **Bugs to Exploit:** 3 (Bugs #9, #10, #11)
  - **Bug #9:** Search endpoint doesn't filter by ownership
  - **Bug #10:** Bulk update skips per-item ownership checks
  - **Bug #11:** Bulk delete by category doesn't check per-item ownership
- **Flags to Capture:** 3
- **Concepts Covered:**
  - Attribute-based access control (ABAC)
  - Batch operation vulnerabilities
  - Query filtering bypasses
  - Loop-based authorization skips
- **Real-World Examples:** Gmail search results, Slack bulk actions, e-commerce bulk deletions

**Run:** `npm run test:04`

---

#### **Exercise 05: Multi-Tenant Isolation & Context Confusion**
- **Difficulty:** ⭐⭐⭐⭐⭐ (Expert)
- **Files Created:**
  - `/exercises/05-multitenant/challenge.md` — Mission briefing
  - `/exercises/05-multitenant/multitenant.test.js` — Jest test suite
- **Bugs to Exploit:** 3 (Bugs #12, #13, #14)
  - **Bug #12:** Organization context from user-controlled headers
  - **Bug #13:** First user to org setup becomes admin without validation
  - **Bug #14:** Org invite doesn't validate caller's authorization
- **Flags to Capture:** 3
- **Concepts Covered:**
  - Multi-tenant architecture
  - Tenant isolation vulnerabilities
  - User-controlled authorization boundaries
  - Cross-tenant data leaks
  - First-user privilege escalation
- **Real-World Examples:** GitHub Organizations, Slack Workspaces, Notion Teams

**Run:** `npm run test:05`

---

### 📖 Comprehensive Walkthrough Guide

**File:** `WALKTHROUGH.md` (4,000+ words)

This is a **complete step-by-step guide** for students that covers:

1. **Setup & Getting Started** — Installation, user accounts, running the server
2. **Exercise 01: IDOR** — Full walkthrough with curl commands
3. **Exercise 02: Vertical Escalation** — All 3 bugs explained and exploited
4. **Exercise 03: JWT Abuse** — Both attack vectors (alg:none + weak secret)
5. **Exercise 04: Context Bypass** — New content showing all 3 exploits
6. **Exercise 05: Multi-Tenant** — New content showing all 3 exploits
7. **Common Mistakes & Debugging** — Troubleshooting guide
8. **Real-World Examples** — Connections to actual vulnerabilities (GitHub, Slack, AWS)

### Key Features of the Walkthrough

✅ **Hands-on** — Uses actual `curl` commands, not just reading  
✅ **Progressive** — Builds from simple (IDOR) to complex (multi-tenant)  
✅ **Educational** — Explains concepts, not just steps  
✅ **Complete** — Covers all 14 bugs across 5 exercises  
✅ **Debugging Help** — Troubleshooting common mistakes  
✅ **Real-world Context** — Shows how these bugs appear in production apps  

---

## Updated Files

### `package.json`
- Added `npm run test:04` script
- Added `npm run test:05` script

### `README.md`
- Updated bug registry from 8 to 14 bugs
- Added Exercise 04 and Exercise 05 descriptions
- Updated scoring from 150 to 245 points
- Updated project structure to include new files

---

## How to Use

### For Students

**Option 1: Quick Start**
```bash
npm run test:01  # Start with IDOR
```

**Option 2: Follow the Walkthrough**
```bash
cat WALKTHROUGH.md  # Read through step by step
npm run test:01     # Try the exercises in order
```

**Option 3: Full Challenge**
```bash
npm test  # Run all exercises at once
```

---

### For Instructors

All exercises follow the same pattern:
- 🔴 **Exploit tests** — PASS when vulnerable, FAIL when fixed
- 🟢 **Hardening tests** — FAIL when vulnerable, PASS when fixed

This allows students to:
1. Confirm they found the bug (exploit test passes)
2. Verify their fix works (hardening tests pass)

---

## Learning Progression

| Exercise | Focus | Time | Difficulty |
|---|---|---|---|
| 01 | Horizontal Escalation (IDOR) | 30 min | ⭐⭐ |
| 02 | Vertical Escalation | 45 min | ⭐⭐⭐ |
| 03 | Cryptographic Failures (JWT) | 60 min | ⭐⭐⭐⭐ |
| 04 | Batch Operation Bypass | 45 min | ⭐⭐⭐⭐ |
| 05 | Multi-Tenant Isolation | 90 min | ⭐⭐⭐⭐⭐ |
| **Total** | **Broken Access Control** | **4 hours** | **Intermediate → Expert** |

---

## Concepts Covered

### Authentication vs Authorization vs Ownership
| Level | Check | Example |
|---|---|---|
| **Authentication** | Are you logged in? | `verifyToken` middleware |
| **Authorization** | Does your role allow this? | `requirePermission('expenses:read')` |
| **Ownership** | Do you own this resource? | `requireOwnership()` middleware |

**Key Insight:** All three must be checked. Missing any one creates a vulnerability.

---

### Access Control Patterns Taught

✅ Role-Based Access Control (RBAC)  
✅ Attribute-Based Access Control (ABAC)  
✅ Permission inheritance and delegation  
✅ Multi-tenant isolation  
✅ Batch operation authorization  
✅ Ownership verification  
✅ JWT security  
✅ Context validation  

---

## Verification

### All Exercises Run Successfully
```bash
# Can start the server
npm start

# Can run individual exercise tests
npm run test:01  # ✅
npm run test:02  # ✅
npm run test:03  # ✅
npm run test:04  # ✅
npm run test:05  # ✅

# Can run all tests
npm test  # ✅
```

### Total Flags Available

**14 flags across 5 exercises:**

1. Exercise 01 (IDOR): 3 flags
2. Exercise 02 (Vertical): 3 flags
3. Exercise 03 (JWT): 2 flags
4. Exercise 04 (Context): 3 flags ← NEW
5. Exercise 05 (Multi-Tenant): 3 flags ← NEW

**Total Points: 245** (with bonus for all hardening tests passing)

---

## What Makes This Lab Practical

Like **DVWA** or **OWASP Juice Shop**, this lab isn't just reading — it's:

✅ **Interactive** — Students use curl to send real HTTP requests  
✅ **Exploit-driven** — Find the bug by actually exploiting it  
✅ **Self-verifying** — Test suite confirms when you've found/fixed each bug  
✅ **Hands-on Code** — Students read and modify actual vulnerable code  
✅ **Progressive** — Exercises build on each other conceptually  
✅ **Real-world** — Each concept is tied to actual production vulnerabilities  

---

## Next Steps for Your Students

1. **Start:** Read `WALKTHROUGH.md` introduction
2. **Exercise 01:** Follow the walkthrough, run curl commands, exploit the bugs
3. **Fix:** Edit `src/app.js`, uncomment missing middleware
4. **Verify:** Run `npm run test:01` — all tests should pass
5. **Repeat:** Exercises 02–05

By the end, students will understand:
- How access control vulnerabilities work
- How to identify them in real code
- How to fix them correctly
- Why these patterns matter in production

---

## Files Summary

| File | Type | Lines | Purpose |
|---|---|---|---|
| `WALKTHROUGH.md` | Guide | 1000+ | Step-by-step for all 5 exercises |
| `exercises/04-context-bypass/challenge.md` | Challenge | 200+ | Exercise 04 mission briefing |
| `exercises/04-context-bypass/context-bypass.test.js` | Tests | 300+ | Exploit & hardening tests for Ex 04 |
| `exercises/05-multitenant/challenge.md` | Challenge | 250+ | Exercise 05 mission briefing |
| `exercises/05-multitenant/multitenant.test.js` | Tests | 350+ | Exploit & hardening tests for Ex 05 |
| `package.json` | Config | — | Added test:04 and test:05 scripts |
| `README.md` | Docs | — | Updated with new exercises |

---

**Ready for students to start learning! 🎓**
