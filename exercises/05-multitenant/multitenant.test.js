/**
 * Exercise 05 — Multi-Tenant Access Control Bypass Test Suite
 *
 * Tests cover:
 *   - Cross-organization data access
 *   - Org context assumption bypass
 *   - First-user admin escalation without validation
 *   - Missing per-request org validation
 *
 * Run:  npm run test:05
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

async function setupOrg(token, orgName) {
  const res = await request(app)
    .post('/api/org/setup')
    .set('Authorization', `Bearer ${token}`)
    .send({ orgName });
  
  if (res.status !== 201) {
    throw new Error(`Org setup failed: ${JSON.stringify(res.body)}`);
  }
  
  return res.body.org;
}

// ─── SETUP ────────────────────────────────────────────────────────────────────

let aliceToken;
let bobToken;
let carolToken;

beforeAll(async () => {
  aliceToken = await getToken('alice');
  bobToken   = await getToken('bob');
  carolToken = await getToken('carol');
});

// ─────────────────────────────────────────────────────────────────────────────
// BUG #12: Organization context not re-validated per request
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #12 — Cross-Org Access via Unvalidated Context Header (GET /api/expenses)', () => {

  // 🔴 EXPLOIT TEST
  test('🔴 [EXPLOIT] User can access other orgs\' expenses via X-Org-Id header', async () => {
    // Setup: Create two orgs, one per user
    const aliceOrg = await setupOrg(aliceToken, 'AliceCorp');
    const bobOrg = await setupOrg(bobToken, 'BobCorp');

    // Alice tries to access BobCorp's expenses by manipulating the header
    const res = await request(app)
      .get('/api/expenses')
      .set('Authorization', `Bearer ${aliceToken}`)
      .set('X-Org-Id', bobOrg.id);  // Trick: set org ID to BobCorp

    // When vulnerable: Alice gets BobCorp's expenses
    expect(res.status).toBe(200);
    expect(res.body.data).toBeDefined();
    
    // Check if there are expenses from BobCorp
    const bobExpenses = res.body.data.filter(exp => exp.orgId === bobOrg.id);
    expect(bobExpenses.length).toBeGreaterThan(0);
    
    expect(res.body.flag).toBe('BAC{cross_org_no_context_validation}');
    console.log('\n  🚩 FLAG CAPTURED:', res.body.flag);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] X-Org-Id header is ignored (org from JWT only)', async () => {
    const aliceOrg = await setupOrg(aliceToken, 'AliceCorp2');
    const bobOrg = await setupOrg(bobToken, 'BobCorp2');

    // Alice tries to see BobCorp
    const res = await request(app)
      .get('/api/expenses')
      .set('Authorization', `Bearer ${aliceToken}`)
      .set('X-Org-Id', bobOrg.id);

    // After fix: should fail or return AliceCorp's expenses only
    if (res.status === 200) {
      // If request succeeds, all expenses must be from Alice's org
      res.body.data.forEach(exp => {
        expect(exp.orgId).toBe(aliceOrg.id);
      });
    } else {
      // Or it should reject outright
      expect(res.status).toBe(403);
    }
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] User can only access expenses in their own org', async () => {
    const aliceOrg = await setupOrg(aliceToken, 'AliceCorp3');

    const res = await request(app)
      .get('/api/expenses')
      .set('Authorization', `Bearer ${aliceToken}`);

    expect(res.status).toBe(200);
    
    // All expenses must belong to Alice's org
    res.body.data.forEach(exp => {
      expect(exp.orgId).toBe(aliceOrg.id);
    });
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// BUG #13: First user to org setup becomes admin without validation
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #13 — Unvalidated First-User = Org Admin Escalation (POST /api/org/setup)', () => {

  // 🔴 EXPLOIT TEST
  test('🔴 [EXPLOIT] Any user can set themselves up as org admin multiple times', async () => {
    // Alice sets up her first org
    const res1 = await request(app)
      .post('/api/org/setup')
      .set('Authorization', `Bearer ${aliceToken}`)
      .send({ orgName: 'AliceOrgA' });

    expect(res1.status).toBe(201);
    expect(res1.body.org.admin.id).toBe(1); // Alice
    
    // Alice sets up a second org (should be denied if fixed)
    const res2 = await request(app)
      .post('/api/org/setup')
      .set('Authorization', `Bearer ${aliceToken}`)
      .send({ orgName: 'AliceOrgB' });

    // When vulnerable: Alice can set up unlimited orgs as admin
    expect(res2.status).toBe(201);
    expect(res2.body.org.admin.id).toBe(1); // Alice again
    
    expect(res2.body.flag).toBe('BAC{org_setup_no_admin_validation}');
    console.log('\n  🚩 FLAG CAPTURED:', res2.body.flag);
  });

  // 🔴 EXPLOIT TEST
  test('🔴 [EXPLOIT] Manager role can set up org and become org admin', async () => {
    // Carol is a manager, should NOT be able to set up and become org admin
    const res = await request(app)
      .post('/api/org/setup')
      .set('Authorization', `Bearer ${carolToken}`)
      .send({ orgName: 'CarolOrg' });

    // When vulnerable: Carol succeeds
    expect(res.status).toBe(201);
    expect(res.body.org.admin.id).toBe(3); // Carol
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] User can only set up one org', async () => {
    // Bob sets up his first org
    const res1 = await request(app)
      .post('/api/org/setup')
      .set('Authorization', `Bearer ${bobToken}`)
      .send({ orgName: 'BobOrg1' });

    expect(res1.status).toBe(201);
    
    // Bob tries to set up a second org
    const res2 = await request(app)
      .post('/api/org/setup')
      .set('Authorization', `Bearer ${bobToken}`)
      .send({ orgName: 'BobOrg2' });

    // Should fail
    expect(res2.status).toBe(400);
    expect(res2.body.error).toContain('already');
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Only user role can set up org, not manager/admin', async () => {
    // Carol (manager) tries to set up org
    const res = await request(app)
      .post('/api/org/setup')
      .set('Authorization', `Bearer ${carolToken}`)
      .send({ orgName: 'UnauthorizedOrg' });

    // Should be rejected
    expect(res.status).toBe(403);
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// BUG #14: Org invite doesn't validate caller's role/org membership
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #14 — Unvalidated Org Invite Allows Privilege Escalation (POST /api/org/invite)', () => {

  // 🔴 EXPLOIT TEST
  test('🔴 [EXPLOIT] User can invite themselves to other orgs with admin role', async () => {
    const aliceOrg = await setupOrg(aliceToken, 'AliceInviteOrg');

    // Bob tries to invite himself to Alice's org as admin
    const res = await request(app)
      .post('/api/org/invite')
      .set('Authorization', `Bearer ${bobToken}`)
      .set('X-Org-Id', aliceOrg.id)
      .send({
        username: 'bob',
        role: 'org_admin',
      });

    // When vulnerable: Bob succeeds in joining Alice's org as admin
    expect(res.status).toBe(201);
    expect(res.body.user.role).toBe('org_admin');
    
    expect(res.body.flag).toBe('BAC{org_invite_no_authorization}');
    console.log('\n  🚩 FLAG CAPTURED:', res.body.flag);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Only org admins can invite users', async () => {
    const aliceOrg = await setupOrg(aliceToken, 'AliceInviteOrgFixed');

    // Bob tries to invite himself (he's not an admin)
    const res = await request(app)
      .post('/api/org/invite')
      .set('Authorization', `Bearer ${bobToken}`)
      .set('X-Org-Id', aliceOrg.id)
      .send({
        username: 'bob',
        role: 'member',
      });

    // Should be rejected
    expect(res.status).toBe(403);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Org admins can only invite to their own org', async () => {
    const aliceOrg = await setupOrg(aliceToken, 'AliceInviteOrgOnlyOwn');
    const bobOrg = await setupOrg(bobToken, 'BobInviteOrg');

    // Alice tries to invite Carol to Bob's org
    const res = await request(app)
      .post('/api/org/invite')
      .set('Authorization', `Bearer ${aliceToken}`)
      .set('X-Org-Id', bobOrg.id)  // Try to manipulate
      .send({
        username: 'carol',
        role: 'member',
      });

    // Should be rejected
    expect(res.status).toBe(403);
  });

});

// Helper for Jest matchers
expect.extend({
  toBeOneOf(received, options) {
    const pass = options.includes(received);
    return {
      pass,
      message: () =>
        `expected ${received} to be one of ${options.join(', ')}`,
    };
  },
});
