# Contributing to the Broken Access Control Lab

Thanks for wanting to extend the lab. This guide is for **instructors and contributors**
who want to add new exercises, improve existing ones, or fix issues.

---

## Lab Design Principles

Before adding anything, internalize these constraints:

1. **Every bug must be exploitable by a student with only curl and Node.** No special tools required until Exercise 03.
2. **Every bug must have a corresponding fix that uses an existing pattern in the codebase.** Students fix bugs by applying the same middleware they already learned, not by inventing new abstractions.
3. **Exploit tests come before hardening tests.** Students must see the vulnerability fire before they fix it — that's the pedagogical sequence.
4. **Flags go in the HTTP response body when the exploit succeeds.** Never in headers, never in logs.
5. **Comments in vulnerable code must describe the bug clearly.** This is a teaching lab, not a CTF that hides the source.

---

## How Bugs Are Structured

Every intentional vulnerability follows this pattern in `src/app.js`:

```javascript
/**
 * ROUTE DESCRIPTION
 *
 * ⚠️  BUG #N — Short name
 *     What the bug is.
 *     What the exploit looks like.
 *     What the fix is.
 */
app.METHOD(
  '/path',
  verifyToken,
  // missingMiddleware(),  ← BUG #N: explanation of why it's commented out
  (req, res) => {
    res.json({ data: ..., flag: 'BAC{flag_string}' });
  }
);
```

The fix is always: uncomment the line, change a string, or replace an inline check.
Never require students to write net-new middleware — only apply existing ones.

---

## Adding a New Exercise

### Step 1 — Design the vulnerability

Answer these questions before writing any code:

- **What category?** (IDOR, vertical escalation, JWT, mass assignment, CORS misconfiguration, etc.)
- **What's the exploit?** Write the curl command first.
- **What's the minimal fix?** One or two lines of code, ideally.
- **Does it fit the ExpenseTracker narrative?** If not, consider extending the data model.
- **What's the flag string?** Format: `BAC{short_descriptor_in_snake_case}`

### Step 2 — Plant the bug

In `src/app.js` (or `src/auth.js` for auth-layer bugs):

```javascript
// Add the vulnerable route with a comment block explaining the bug
// Embed the flag in the response body
// Assign it the next bug number in sequence
```

Update the bug registry comment at the top of `src/app.js`.

### Step 3 — Create the exercise folder

```
exercises/
└── 04-your-exercise/
    ├── challenge.md        ← mission briefing + curl commands + patch guide
    └── your-exercise.test.js  ← Jest test suite
```

### Step 4 — Write the tests

Follow the existing test structure exactly:

```javascript
describe('Bug #N — Short Name (ROUTE)', () => {

  // 🔴 EXPLOIT TEST — passes when vulnerable, fails after fix
  test('🔴 [EXPLOIT] Description of what the exploit does', async () => {
    // ...
    expect(res.body.flag).toBe('BAC{your_flag}');
  });

  // 🟢 HARDENING TEST — fails when vulnerable, passes after fix
  test('🟢 [HARDENING] Description of what the fix enforces', async () => {
    // ...
    expect(res.status).toBe(403);
  });

});
```

**Rules for tests:**
- Every exploit test must capture a flag in the assertion
- Every hardening test must check a specific HTTP status code and error shape
- Legitimate users of the right role must still be able to use the feature after the fix (always add a "role X can still do Y" hardening test)
- Unauthenticated requests must always return 401 (add this test to every describe block)

### Step 5 — Add the npm script

In `package.json`:

```json
"test:04": "jest exercises/04-your-exercise --runInBand --forceExit --verbose"
```

### Step 6 — Update the README

Add a row to the vulnerability map table (inside the `<details>` spoiler block)
and add a new exercise entry under the Exercises section.

### Step 7 — Update the solutions repo

Add the patched version of the affected file(s) to the private solutions repository.
Document which lines changed and why.

---

## Exercise Categories Still Available

The following vulnerability classes are **not yet covered** and would make strong additions:

| Category | OWASP | Description |
|---|---|---|
| Mass Assignment | A01 | `req.body` passed directly to update — allows `role` field to be set by user |
| CORS Misconfiguration | A05 | `Access-Control-Allow-Origin: *` on credentialed endpoints |
| Path Traversal | A01 | File download endpoint that doesn't sanitize `../` sequences |
| Function-level Access Control | A01 | HTTP verb confusion — `GET` allowed, `POST` to same path is not guarded |
| JWT `kid` Injection | A02 | `kid` header used in SQL query or file path without sanitization |
| Regex DoS on roles | A05 | Permission check uses a regex that can be catastrophically backtracked |

---

## Test Quality Checklist

Before submitting a PR, verify:

- [ ] All exploit tests include a `console.log` that prints the captured flag
- [ ] All hardening tests check both the HTTP status code AND the error body shape
- [ ] No test depends on ordering (each `describe` block sets up its own state)
- [ ] `beforeAll` uses only the login endpoint, never hardcoded tokens
- [ ] Tests pass cleanly with `npm run test:XX --forceExit`
- [ ] The challenge.md has Phase 1 through Phase 5 (Recon, Exploit, Root Cause, Patch, Verify)
- [ ] The flag format matches `BAC{snake_case_descriptor}`

---

## Submitting

1. Fork the repo
2. Create a branch: `git checkout -b exercise/04-mass-assignment`
3. Follow the steps above
4. Open a PR with:
   - A description of the vulnerability
   - The exploit curl command in the PR body
   - Confirmation that `npm test` passes with all existing tests still green

---

## Code Style

- `'single quotes'` throughout
- `const` over `let`, never `var`
- All async route handlers use `async/await`, not callbacks
- Error responses always have the shape `{ error: 'string', ... }`
- Success responses always wrap data in `{ data: ... }`
- Bug comments use the `⚠️  BUG #N` prefix so they're grep-able:
  ```bash
  grep -n "⚠️" src/app.js
  ```

---

## Questions

Open an issue on the repo or contact the lab maintainer directly.
