/**
 * Exercise 02 — Vertical Privilege Escalation Test Suite
 *
 * HOW TO READ THESE TESTS
 * ───────────────────────
 * 🔴 EXPLOIT TESTS  — PASS when vulnerable, should FAIL after your fix.
 * 🟢 HARDENING TESTS — FAIL when vulnerable, should PASS after your fix.
 *
 * Run:  npm run test:02
 */

const request = require('supertest');
const app = require('../../src/app');

// ─── HELPERS ──────────────────────────────────────────────────────────────────

async function getToken(username, password = 'password123') {
  const res = await request(app)
    .post('/api/auth/login')
    .send({ username, password });
  if (res.status !== 200) throw new Error(`Login failed for ${username}`);
  return res.body.token;
}

// ─── SETUP ────────────────────────────────────────────────────────────────────

let userToken;      // alice — role: user
let managerToken;   // carol — role: manager
let adminToken;     // admin — role: admin

beforeAll(async () => {
  userToken    = await getToken('alice');
  managerToken = await getToken('carol');
  adminToken   = await getToken('admin', 'adminpass');
});

// ─────────────────────────────────────────────────────────────────────────────
// BUG #4: Missing permission guard on GET /api/admin/users
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #4 — No Permission Check on Admin Route (GET /api/admin/users)', () => {

  // 🔴 EXPLOIT TEST
  test('🔴 [EXPLOIT] User role can access admin user list', async () => {
    const res = await request(app)
      .get('/api/admin/users')
      .set('Authorization', `Bearer ${userToken}`);

    // When vulnerable: user gets full user list
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
    expect(res.body.flag).toBe('BAC{vertical_escalation_no_permission_check}');

    console.log('\n  🚩 FLAG CAPTURED:', res.body.flag);
    console.log('  Users exposed:', res.body.data.map((u) => u.username));
  });

  // 🔴 EXPLOIT TEST
  test('🔴 [EXPLOIT] Manager role can also access admin user list (currently ungated)', async () => {
    const res = await request(app)
      .get('/api/admin/users')
      .set('Authorization', `Bearer ${managerToken}`);

    // Manager can also hit this (no check at all currently)
    expect(res.status).toBe(200);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] User role is denied access to admin user list', async () => {
    const res = await request(app)
      .get('/api/admin/users')
      .set('Authorization', `Bearer ${userToken}`);

    expect(res.status).toBe(403);
    expect(res.body.error).toBe('Access Denied');
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Manager role is denied access to admin user list', async () => {
    const res = await request(app)
      .get('/api/admin/users')
      .set('Authorization', `Bearer ${managerToken}`);

    // Managers don't have 'users:read' — should be 403
    expect(res.status).toBe(403);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Admin role can access user list', async () => {
    const res = await request(app)
      .get('/api/admin/users')
      .set('Authorization', `Bearer ${adminToken}`);

    // Only admin should get through
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Unauthenticated request is rejected', async () => {
    const res = await request(app).get('/api/admin/users');
    expect(res.status).toBe(401);
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// BUG #5: Wrong permission string on DELETE /api/expenses/:id
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #5 — Wrong Permission String on Delete Route (DELETE /api/expenses/:id)', () => {

  // 🔴 EXPLOIT TEST
  test('🔴 [EXPLOIT] User role can delete expenses (wrong permission checked)', async () => {
    const res = await request(app)
      .delete('/api/expenses/7')   // Carol's expense — user shouldn't be able to delete any expense
      .set('Authorization', `Bearer ${userToken}`);

    // When vulnerable: 'expenses:read' is checked (user HAS this), so deletion succeeds
    expect(res.status).toBe(200);
    expect(res.body.flag).toContain('BAC{');

    console.log('\n  🚩 FLAG CAPTURED:', res.body.flag);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] User role is denied delete on expenses they don\'t own', async () => {
    const res = await request(app)
      .delete('/api/expenses/6')
      .set('Authorization', `Bearer ${userToken}`);

    // After fixing both Bug #5 (wrong permission) and Bug #3 (no ownership check):
    // User with no 'expenses:delete_own' should get 403
    expect(res.status).toBe(403);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Admin role can still delete any expense', async () => {
    const res = await request(app)
      .delete('/api/expenses/2')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// BUG #6: Manual role check on POST /api/expenses/approve/:id
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #6 — Manual Role Check Bypasses Permission System (POST /api/expenses/approve/:id)', () => {

  // 🔴 EXPLOIT TEST (inverted — the bug BLOCKS legitimate users)
  // The "exploit" here is exposing that managers are incorrectly denied.
  // The flag appears in the 403 response body as a hint.
  test('🔴 [EXPLOIT] Manager is incorrectly denied approve access — flag in error body', async () => {
    const res = await request(app)
      .post('/api/expenses/approve/6')
      .set('Authorization', `Bearer ${managerToken}`);

    // Manager SHOULD be allowed (per PERMISSIONS map) but the manual check blocks them
    // The flag is returned in the error body to signal the bug was found
    expect(res.status).toBe(403);
    expect(res.body.flag).toBe('BAC{manual_role_check_bypasses_permission_system}');

    console.log('\n  🚩 FLAG CAPTURED:', res.body.flag);
    console.log('  Bug: manual role check incorrectly blocked a manager');
  });

  // 🔴 EXPLOIT TEST
  test('🔴 [EXPLOIT] User role is also blocked (expected) — but for the wrong reason', async () => {
    const res = await request(app)
      .post('/api/expenses/approve/6')
      .set('Authorization', `Bearer ${userToken}`);

    // User is correctly blocked (they shouldn't approve) but the reason is
    // a hardcoded role check, not the permission system.
    // After fix: this should still be 403, but now routed through requirePermission()
    expect(res.status).toBe(403);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Manager can approve expenses after fix', async () => {
    const res = await request(app)
      .post('/api/expenses/approve/1')
      .set('Authorization', `Bearer ${managerToken}`);

    // After fixing to requirePermission('expenses:approve'),
    // managers (who have this permission) should get through
    expect(res.status).toBe(200);
    expect(res.body.data.status).toBe('approved');
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Admin can approve expenses', async () => {
    const res = await request(app)
      .post('/api/expenses/approve/2')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(res.body.data.status).toBe('approved');
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] User role cannot approve expenses', async () => {
    const res = await request(app)
      .post('/api/expenses/approve/3')
      .set('Authorization', `Bearer ${userToken}`);

    expect(res.status).toBe(403);
    // After fix: error comes from requirePermission, not a manual check
    expect(res.body.error).toBe('Access Denied');
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Unauthenticated approve attempt is rejected', async () => {
    const res = await request(app)
      .post('/api/expenses/approve/1');

    expect(res.status).toBe(401);
  });

});
