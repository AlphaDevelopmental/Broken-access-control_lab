/**
 * auth.js — Mock JWT Authentication
 *
 * Provides:
 *   - POST /api/auth/login  → issues a signed JWT
 *   - verifyToken()         → middleware that validates incoming JWTs
 *
 * ─── VULNERABILITY PLANTED (Exercise 03) ────────────────────────────────────
 *
 * BUG #8 — Weak signing secret
 *   JWT_SECRET is hardcoded as the string "secret".
 *   A real attacker would crack this in seconds with a wordlist attack,
 *   then re-sign any payload they want (e.g. role: "admin").
 *
 * BUG #7 — Algorithm confusion (alg: none)
 *   verifyToken() does NOT pass `algorithms` to jwt.verify().
 *   This means it will accept tokens signed with alg:"none" — i.e. unsigned.
 *   An attacker can craft { "alg": "none" } header + { role: "admin" } payload
 *   and the server accepts it without any signature check.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 */

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { findUserByUsername } = require('./data');

// BUG #8: This secret is laughably weak. `jwt-cracker` or `hashcat`
// will brute-force it in under a second against common wordlists.
const JWT_SECRET = 'secret';

const TOKEN_EXPIRY = '2h';

// ─── LOGIN ────────────────────────────────────────────────────────────────────

/**
 * loginHandler
 * POST /api/auth/login
 * Body: { username, password }
 * Returns: { token, user: { id, username, role } }
 */
async function loginHandler(req, res) {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }

  const user = findUserByUsername(username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const payload = {
    userId: user.id,
    role: user.role,
  };

  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });

  return res.status(200).json({
    token,
    user: { id: user.id, username: user.username, role: user.role },
  });
}

// ─── VERIFY TOKEN MIDDLEWARE ──────────────────────────────────────────────────

/**
 * verifyToken
 * Reads Authorization: Bearer <token>, decodes it, and attaches
 * the decoded payload to req.user.
 *
 * BUG #7: Missing algorithm whitelist in jwt.verify().
 * The current code accepts tokens with alg:none (unsigned) after manual parsing.
 * Fix: pass { algorithms: ['HS256'] } as the options to reject unsigned tokens.
 */
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    // ⚠️  BUG #7 IS HERE — vulnerable code accepts alg:none tokens
    // First, try normal JWT verification
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    } catch (err) {
      // If verification fails, check if it's an unsigned (alg:none) token
      // Vulnerable code would accept this - fix by only allowing HS256
      const parts = token.split('.');
      if (parts.length === 3) {
        try {
          const headerB64 = parts[0];
          const payloadB64 = parts[1];
          const signature = parts[2];
          
          const headerJson = JSON.parse(
            Buffer.from(headerB64, 'base64url').toString('utf8')
          );
          
          // BUG #7: When alg is 'none' and signature is empty, accept it (vulnerable)
          if (headerJson.alg === 'none' && signature === '') {
            decoded = JSON.parse(
              Buffer.from(payloadB64, 'base64url').toString('utf8')
            );
          } else {
            throw err;
          }
        } catch (parseErr) {
          throw err;
        }
      } else {
        throw err;
      }
    }
    
    req.user = decoded; // { userId, role, iat, exp }
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ─── EXPORTS ──────────────────────────────────────────────────────────────────

module.exports = { loginHandler, verifyToken, JWT_SECRET };
