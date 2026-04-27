/**
 * Exercise 04 — Context/Attribute-Based Access Control Bypass Test Suite
 *
 * Tests cover three categories of bugs:
 *   - Search without ownership filter
 *   - Bulk updates without per-item ownership checks
 *   - Bulk deletes without per-item ownership checks
 *
 * Run:  npm run test:04
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
let adminToken;     // admin — role: admin

beforeAll(async () => {
  userToken  = await getToken('alice');
  adminToken = await getToken('admin', 'adminpass');
});

// ─────────────────────────────────────────────────────────────────────────────
// BUG #9: Search endpoint doesn't filter by ownership
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #9 — Search Doesn\'t Filter by Ownership (GET /api/expenses/search)', () => {

  // 🔴 EXPLOIT TEST
  test('🔴 [EXPLOIT] User can search and find other users\' expenses', async () => {
    const res = await request(app)
      .get('/api/expenses/search')
      .query({ category: 'travel' })
      .set('Authorization', `Bearer ${userToken}`);

    // When vulnerable: Alice sees ALL travel expenses, not just hers
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data)).toBe(true);
    
    // Check if there are expenses from other users
    const otherUsersExpenses = res.body.data.filter(exp => exp.ownerId !== 1);
    expect(otherUsersExpenses.length).toBeGreaterThan(0);
    
    expect(res.body.flag).toBe('BAC{search_no_ownership_filter}');
    console.log('\n  🚩 FLAG CAPTURED:', res.body.flag);
    console.log('  Found', otherUsersExpenses.length, 'expenses from other users');
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] User search results are filtered to only their own expenses', async () => {
    const res = await request(app)
      .get('/api/expenses/search')
      .query({ category: 'travel' })
      .set('Authorization', `Bearer ${userToken}`);

    expect(res.status).toBe(200);
    
    // All returned expenses must belong to Alice (userId: 1)
    if (res.body.data.length > 0) {
      res.body.data.forEach(exp => {
        expect(exp.ownerId).toBe(1);
      });
    }
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Admin can see all expenses regardless of category', async () => {
    const res = await request(app)
      .get('/api/expenses/search')
      .query({ category: 'travel' })
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    // Admin should see all travel expenses (no filter)
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// BUG #10: Bulk update doesn't check ownership per item
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #10 — Bulk Update Missing Per-Item Ownership Checks (POST /api/expenses/bulk-update)', () => {

  // 🔴 EXPLOIT TEST
  test('🔴 [EXPLOIT] User can bulk-update other users\' expenses', async () => {
    const res = await request(app)
      .post('/api/expenses/bulk-update')
      .set('Authorization', `Bearer ${userToken}`)
      .send({
        ids: [4, 5],  // Bob's expenses
        status: 'approved',
      });

    // When vulnerable: bulk update succeeds on all items
    expect(res.status).toBe(200);
    expect(res.body.results).toBeDefined();
    
    // All updates should succeed (bug)
    const successCount = res.body.results.filter(r => r.success === true).length;
    expect(successCount).toBe(2);
    
    expect(res.body.flag).toBe('BAC{bulk_update_no_item_checks}');
    console.log('\n  🚩 FLAG CAPTURED:', res.body.flag);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] User bulk-update fails on expenses they don\'t own', async () => {
    const res = await request(app)
      .post('/api/expenses/bulk-update')
      .set('Authorization', `Bearer ${userToken}`)
      .send({
        ids: [4, 5],  // Bob's expenses
        status: 'approved',
      });

    // After fix: should fail or return mixed results
    // Option A: Return 403 entirely
    // Option B: Return 200 with per-item errors
    expect(res.status).toBeOneOf([403, 200]);
    
    if (res.status === 200 && res.body.results) {
      // If returning mixed, Bob's expenses should have errors
      const bobResults = res.body.results;
      bobResults.forEach(result => {
        if (result.id > 3) {  // ids 4-5 are Bob's
          expect(result.success).toBe(false);
        }
      });
    }
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] User can bulk-update only their own expenses', async () => {
    const res = await request(app)
      .post('/api/expenses/bulk-update')
      .set('Authorization', `Bearer ${userToken}`)
      .send({
        ids: [1, 2, 3],  // Alice's expenses only
        status: 'pending',
      });

    expect(res.status).toBe(200);
    if (res.body.results) {
      res.body.results.forEach(result => {
        expect(result.success).toBe(true);
      });
    }
  });

});

// ─────────────────────────────────────────────────────────────────────────────
// BUG #11: Bulk delete by category doesn't check per-item ownership
// ─────────────────────────────────────────────────────────────────────────────

describe('Bug #11 — Bulk Delete by Category Missing Item Checks (DELETE /api/expenses/category/:category)', () => {

  // 🔴 EXPLOIT TEST
  test('🔴 [EXPLOIT] User can bulk-delete other users\' expenses by category', async () => {
    const res = await request(app)
      .delete('/api/expenses/category/misc')
      .set('Authorization', `Bearer ${userToken}`);

    // When vulnerable: Alice deletes ALL misc expenses, including Bob's
    expect(res.status).toBe(200);
    expect(res.body.deleted).toBeDefined();
    
    // Should show expenses from other users were deleted
    const otherUsersDeleted = res.body.results?.filter(r => r.ownerId !== 1).length || 0;
    expect(otherUsersDeleted).toBeGreaterThan(0);
    
    expect(res.body.flag).toBe('BAC{bulk_delete_no_item_checks}');
    console.log('\n  🚩 FLAG CAPTURED:', res.body.flag);
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] User bulk-delete only deletes their own expenses in category', async () => {
    const res = await request(app)
      .delete('/api/expenses/category/travel')
      .set('Authorization', `Bearer ${userToken}`);

    expect(res.status).toBe(200);
    
    // Only user's own expenses should be deleted
    if (res.body.results) {
      res.body.results.forEach(result => {
        expect(result.ownerId).toBe(1);  // Alice only
      });
    }
  });

  // 🟢 HARDENING TEST
  test('🟢 [HARDENING] Admin can bulk-delete all expenses in a category', async () => {
    const res = await request(app)
      .delete('/api/expenses/category/food')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
  });

});

// Helper for toBeOneOf matcher
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
