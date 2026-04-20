/**
 * Exercise 01 — IDOR Test Suite
 *
 * HOW TO READ THESE TESTS
 * ───────────────────────
 * 🔴 EXPLOIT TESTS
 *    These tests PASS when the vulnerability exists.
 *    After you patch the code, they should FAIL.
 *    A passing exploit test = you confirmed the bug.
 *    A failing exploit test = you fixed it. ✅
 *
 * 🟢 HARDENING TESTS
 *    These tests FAIL when the vulnerability exists.
 *    After you patch the code, they should PASS.
 *    A passing hardening test = your fix is working.
 *
 * Run:  npm run test:01
 */

const request = require('supertest');
const app = require('../../src/app');

// ─── HELPERS ──────────────────────────────────────────────────────────────────

/**
 * Login as a given user and return the JWT token.
 */
async function getToken(username, password = 'password123') {
  const res = await request(app)
    .post('/api/auth/login')
    .send({ username, password });

  if (res.status !== 200) {
    throw new Error(`Login failed for ${username}: ${JSON.stringify(res.body)}`);
  }
  return res.body.token;
}

// ─── SETUP ────────────────────────────────────────────────────────────────────

let aliceToken;
let bobToken;
let managerToken;

beforeAll(async () => {
  aliceToken = await getToken('alice');   // role: user, owns expenses 1-3
  bobToken   = await getToken('bob');     // role: user, owns expenses 4-5
  managerToken = await getToken('carol'); // role: manager
});

// ─────────────────────────────────────────────────────────────────────────────
// BUG #1: IDOR READ
// GET /api/expenses/:id — no ownership check
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #1 — IDOR Read (GET /api/expenses/:id)', () => {

  // 🔴 EXPLOIT TEST
  // This PASSES when vulnerable. Should FAIL after your fix.
  test('🔴 [EXPLOIT] Alice can read Bob\'s expense (id=4)', async () => {
    const res = await request(app)
      .get('/api/expenses/4')
      .set('Authorization', `Bearer ${aliceToken}`);

    // When vulnerable: Alice gets Bob's data back with a 200
    expect(res.status).toBe(200);
    expect(res.body.data.ownerId).toBe(2); // Bob's id is 2
    expect(res.body.flag).toBe('BAC{idor_read_unlocked}');

    console.log('\n  🚩 FLAG CAPTURED:', res.body.flag);
  });

  // 🔴 EXPLOIT TEST
  test('🔴 [EXPLOIT] Alice can read Carol\'s expense (id=6)', async () => {
    const res = await request(app)
      .get('/api/expenses/6')
      .set('Authorization', `Bearer ${aliceToken}`);

    expect(res.status).toBe(200);
    expect(res.body.data.ownerId).toBe(3); // Carol's id is 3
  });

  // 🟢 HARDENING TEST
  // This FAILS when vulnerable. Should PASS after your fix.
  test('🟢 [HARDENING] Alice cannot read Bob\'s expense after fix', async () => {
    const res = await request(app)
      .get('/api/expenses/4')
      .set('Authorization', `Bearer ${aliceToken}`);

    // After fix: should be 403 Forbidden
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('Access Denied');
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Alice can still read her own expense (id=1)', async () => {
    const res = await request(app)
      .get('/api/expenses/1')
      .set('Authorization', `Bearer ${aliceToken}`);

    // After fix: Alice's own expense still accessible
    expect(res.status).toBe(200);
    expect(res.body.data.ownerId).toBe(1); // Alice's id is 1
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Bob can read his own expense (id=4)', async () => {
    const res = await request(app)
      .get('/api/expenses/4')
      .set('Authorization', `Bearer ${bobToken}`);

    expect(res.status).toBe(200);
    expect(res.body.data.ownerId).toBe(2);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Manager can read any expense (role bypass expected)', async () => {
    const res = await request(app)
      .get('/api/expenses/1')
      .set('Authorization', `Bearer ${managerToken}`);

    // Managers bypass ownership — this should still be 200 after fix
    expect(res.status).toBe(200);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Unauthenticated request is rejected', async () => {
    const res = await request(app).get('/api/expenses/1');
    expect(res.status).toBe(401);
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// BUG #2: IDOR WRITE
// PUT /api/expenses/:id — no ownership check
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #2 — IDOR Write (PUT /api/expenses/:id)', () => {

  // 🔴 EXPLOIT TEST
  test('🔴 [EXPLOIT] Alice can modify Bob\'s expense (id=5)', async () => {
    const res = await request(app)
      .put('/api/expenses/5')
      .set('Authorization', `Bearer ${aliceToken}`)
      .send({ title: 'Tampered by Alice', amount: 0.01 });

    expect(res.status).toBe(200);
    expect(res.body.flag).toBe('BAC{idor_write_unlocked}');

    console.log('\n  🚩 FLAG CAPTURED:', res.body.flag);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Alice cannot modify Bob\'s expense after fix', async () => {
    const res = await request(app)
      .put('/api/expenses/5')
      .set('Authorization', `Bearer ${aliceToken}`)
      .send({ title: 'Still trying', amount: 0.01 });

    expect(res.status).toBe(403);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Alice can update her own expense (id=2)', async () => {
    const res = await request(app)
      .put('/api/expenses/2')
      .set('Authorization', `Bearer ${aliceToken}`)
      .send({ title: 'Updated by Alice (legitimate)', amount: 25.0 });

    expect(res.status).toBe(200);
    expect(res.body.data.title).toBe('Updated by Alice (legitimate)');
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// BUG #3: IDOR DELETE (overlaps with Bug #5 — see Exercise 02)
// DELETE /api/expenses/:id — missing ownership check + wrong permission
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #3 — IDOR Delete (DELETE /api/expenses/:id)', () => {

  // 🔴 EXPLOIT TEST
  // Note: this exploits BOTH Bug #3 (no ownership) AND Bug #5 (wrong permission).
  // Even if you fix Bug #5 first, Bug #3 still allows cross-user deletion.
  test('🔴 [EXPLOIT] Alice can delete Bob\'s expense (id=4)', async () => {
    const res = await request(app)
      .delete('/api/expenses/4')
      .set('Authorization', `Bearer ${aliceToken}`);

    expect(res.status).toBe(200);
    expect(res.body.flag).toContain('BAC{');

    console.log('\n  🚩 FLAG CAPTURED:', res.body.flag);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Alice cannot delete Bob\'s expense after fix', async () => {
    const res = await request(app)
      .delete('/api/expenses/5')
      .set('Authorization', `Bearer ${aliceToken}`);

    expect(res.status).toBe(403);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Alice can delete her own expense (id=3)', async () => {
    const res = await request(app)
      .delete('/api/expenses/3')
      .set('Authorization', `Bearer ${aliceToken}`);

    expect(res.status).toBe(200);
  });

});
