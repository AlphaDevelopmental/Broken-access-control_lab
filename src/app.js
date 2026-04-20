/**
 * app.js — ExpenseTracker API Server
 *
 * This is the intentionally vulnerable Express application.
 * It contains 6 access-control bugs across its routes.
 * (Bugs #7 and #8 live in auth.js)
 *
 * ─── BUG REGISTRY ────────────────────────────────────────────────────────────
 *
 *  #1  GET  /api/expenses/:id          IDOR read    — missing requireOwnership()
 *  #2  PUT  /api/expenses/:id          IDOR write   — missing requireOwnership()
 *  #3  DELETE /api/expenses/:id        IDOR delete  — missing requireOwnership()
 *       └─ also Bug #5: wrong permission string used ('expenses:read' → should
 *          be 'expenses:delete' for admin path, 'expenses:delete_own' for user)
 *
 *  #4  GET  /api/admin/users           Vertical     — requirePermission() never applied
 *  #5  DELETE /api/expenses/:id        Vertical     — wrong permission checked
 *  #6  POST /api/expenses/approve/:id  Vertical     — manual role check instead
 *                                                     of requirePermission()
 *
 * ─────────────────────────────────────────────────────────────────────────────
 */

'use strict';

const express = require('express');
const { loginHandler, verifyToken } = require('./auth');
const { requirePermission, requireOwnership } = require('./middleware');
const {
  findExpenseById,
  findExpensesByOwner,
  getAllExpenses,
  getAllUsers,
  updateExpense,
  deleteExpense,
} = require('./data');

const app = express();
app.use(express.json());

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

/**
 * POST /api/auth/login
 * Public endpoint. Returns a JWT on valid credentials.
 *
 * Body:   { "username": "alice", "password": "password123" }
 * Returns: { "token": "eyJ...", "user": { id, username, role } }
 */
app.post('/api/auth/login', loginHandler);

// ─── EXPENSE ROUTES ───────────────────────────────────────────────────────────

/**
 * GET /api/expenses
 * List all expenses (manager/admin) or own expenses (user).
 * Correctly protected.
 */
app.get(
  '/api/expenses',
  verifyToken,
  requirePermission('expenses:read'),
  (req, res) => {
    const expenses = getAllExpenses();
    res.json({ data: expenses });
  }
);

/**
 * GET /api/expenses/mine
 * List the current user's own expenses.
 * Correctly protected.
 */
app.get(
  '/api/expenses/mine',
  verifyToken,
  requirePermission('expenses:read_own'),
  (req, res) => {
    const expenses = findExpensesByOwner(req.user.userId);
    res.json({ data: expenses });
  }
);

/**
 * GET /api/expenses/:id
 * Read a single expense by ID.
 *
 * ⚠️  BUG #1 — IDOR Read
 *     requireOwnership() is missing. Any authenticated user can read
 *     any expense by guessing the ID, regardless of who owns it.
 *
 *     Exploit:  Log in as Alice. Request GET /api/expenses/4 (Bob's expense).
 *               You receive Bob's data + the flag.
 *
 *     Fix:      Add requireOwnership() after requirePermission().
 */
app.get(
  '/api/expenses/:id',
  verifyToken,
  requirePermission('expenses:read_own'),
  // requireOwnership(),  ← BUG #1: this line is intentionally commented out
  (req, res) => {
    const expense = findExpenseById(req.params.id);
    if (!expense) return res.status(404).json({ error: 'Expense not found' });

    // Flag is exposed because ownership was never checked
    res.json({ data: expense, flag: expense.flag });
  }
);

/**
 * POST /api/expenses
 * Create a new expense for the current user.
 * Correctly protected.
 */
app.post(
  '/api/expenses',
  verifyToken,
  requirePermission('expenses:write_own'),
  (req, res) => {
    const { title, amount, category } = req.body;
    if (!title || !amount) {
      return res.status(400).json({ error: 'title and amount are required' });
    }
    // Simplified: in a real app you'd insert into DB
    const newExpense = {
      id: Date.now(),
      ownerId: req.user.userId,
      title,
      amount: parseFloat(amount),
      category: category || 'misc',
      status: 'pending',
      date: new Date().toISOString().split('T')[0],
      flag: null,
    };
    res.status(201).json({ data: newExpense });
  }
);

/**
 * PUT /api/expenses/:id
 * Update an expense.
 *
 * ⚠️  BUG #2 — IDOR Write
 *     requireOwnership() is missing. Any authenticated user can overwrite
 *     any expense's data by sending a PUT to an arbitrary ID.
 *
 *     Exploit:  Log in as Alice. PUT /api/expenses/4 with new amount.
 *               Bob's expense is modified. Flag returned.
 *
 *     Fix:      Add requireOwnership() after requirePermission().
 */
app.put(
  '/api/expenses/:id',
  verifyToken,
  requirePermission('expenses:update_own'),
  // requireOwnership(),  ← BUG #2: intentionally missing
  (req, res) => {
    const expense = findExpenseById(req.params.id);
    if (!expense) return res.status(404).json({ error: 'Expense not found' });

    const updated = updateExpense(req.params.id, req.body);
    res.json({
      data: updated,
      flag: 'BAC{idor_write_unlocked}', // exposed because no ownership check
    });
  }
);

/**
 * DELETE /api/expenses/:id
 * Delete an expense.
 *
 * ⚠️  BUG #3 — IDOR Delete
 *     requireOwnership() is missing.
 *
 * ⚠️  BUG #5 — Wrong permission string
 *     This route checks 'expenses:read' (a permission ALL users have)
 *     instead of 'expenses:delete_own'. A 'user' role can therefore hit
 *     this route without any vertical escalation at all.
 *
 *     Exploit A (vertical, Bug #5):
 *       Log in as Alice (role: user).
 *       DELETE /api/expenses/1 — succeeds because 'expenses:read' is checked,
 *       not 'expenses:delete_own'.
 *
 *     Exploit B (horizontal, Bug #3):
 *       Even after fixing Bug #5, without requireOwnership() Alice can still
 *       delete Bob's expense #4.
 *
 *     Fix:      1. Change permission to 'expenses:delete_own'
 *               2. Add requireOwnership()
 */
app.delete(
  '/api/expenses/:id',
  verifyToken,
  requirePermission('expenses:read'), // ⚠️  BUG #5: should be 'expenses:delete_own'
  // requireOwnership(),               // ⚠️  BUG #3: intentionally missing
  (req, res) => {
    const expense = findExpenseById(req.params.id);
    if (!expense) return res.status(404).json({ error: 'Expense not found' });

    deleteExpense(req.params.id);
    res.json({
      message: 'Expense deleted.',
      flag: 'BAC{idor_delete_and_vertical_unlocked}',
    });
  }
);

// ─── APPROVAL ROUTE ───────────────────────────────────────────────────────────

/**
 * POST /api/expenses/approve/:id
 * Approve an expense (manager+ only).
 *
 * ⚠️  BUG #6 — Manual role check bypasses permission system
 *     Instead of using requirePermission('expenses:approve'), this route
 *     does a manual inline check: if (req.user.role !== 'admin').
 *     Problems:
 *       a) 'manager' role should also be able to approve — this blocks them.
 *       b) Manual checks are brittle, easy to misconfigure, and bypass
 *          the centralized PERMISSIONS registry entirely.
 *       c) Worse: 'manager' is blocked but the check string could be
 *          trivially bypassed if the role value is ever normalized differently.
 *
 *     Fix: Replace the inline check with requirePermission('expenses:approve').
 */
app.post(
  '/api/expenses/approve/:id',
  verifyToken,
  (req, res, next) => {
    // ⚠️  BUG #6: manual role check — not using requirePermission()
    if (req.user.role !== 'admin') {
      // This accidentally blocks managers too (they should be allowed)
      // and doesn't use the centralized permission registry
      return res.status(403).json({
        error: 'Access Denied',
        note: 'Only admins can approve. (But should managers be able to? The PERMISSIONS map says yes...)',
        flag: 'BAC{manual_role_check_bypasses_permission_system}',
      });
    }
    next();
  },
  (req, res) => {
    const expense = findExpenseById(req.params.id);
    if (!expense) return res.status(404).json({ error: 'Expense not found' });

    const updated = updateExpense(req.params.id, { status: 'approved' });
    res.json({ data: updated, message: 'Expense approved.' });
  }
);

// ─── ADMIN ROUTES ─────────────────────────────────────────────────────────────

/**
 * GET /api/admin/users
 * List all users (admin only).
 *
 * ⚠️  BUG #4 — requirePermission() never applied
 *     verifyToken is present (user must be logged in), but there is
 *     no permission check at all. Any authenticated user — even role: 'user' —
 *     can retrieve the full user list.
 *
 *     Exploit: Log in as Alice (role: user). GET /api/admin/users → 200 OK.
 *
 *     Fix:     Add requirePermission('users:read') after verifyToken.
 */
app.get(
  '/api/admin/users',
  verifyToken,
  // requirePermission('users:read'),  ← BUG #4: intentionally missing
  (req, res) => {
    const users = getAllUsers();

    // Determine which flag to award based on how the caller got here.
    //
    // Three ways to reach this endpoint without an admin account:
    //   A) Bug #4: legitimate user token, no permission check applied → vertical escalation flag
    //   B) Bug #7: alg:none forged token → JWT algorithm confusion flag
    //   C) Bug #8: re-signed token using cracked secret → weak secret flag
    //
    // We detect B and C by inspecting the decoded token on req.user:
    //   - userId: 99 is the sentinel used in the test exploit payloads
    //   - alg:none tokens arrive with req.user.userId === 99 and no iat issued by our login system
    //   - re-signed tokens also use userId: 99 but are properly HS256-signed

    let flag = 'BAC{vertical_escalation_no_permission_check}'; // default: Bug #4

    if (req.user?.userId === 99) {
      // Forged token: check the Authorization header to distinguish alg:none vs re-signed
      const authHeader = req.headers['authorization'] || '';
      const token = authHeader.split(' ')[1] || '';
      const headerB64 = token.split('.')[0] || '';

      try {
        const headerJson = JSON.parse(
          Buffer.from(headerB64, 'base64url').toString('utf8')
        );
        if (headerJson.alg === 'none') {
          flag = 'BAC{jwt_alg_none_accepted}';       // Bug #7
        } else {
          flag = 'BAC{jwt_weak_secret_cracked}';     // Bug #8
        }
      } catch {
        flag = 'BAC{jwt_weak_secret_cracked}';       // fallback for Bug #8
      }
    }

    res.json({ data: users, flag });
  }
);

/**
 * GET /api/health
 * Public health check — no auth required.
 */
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', app: 'ExpenseTracker API' });
});

// ─── 404 FALLBACK ─────────────────────────────────────────────────────────────

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// ─── START ────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;

// Only start listening if this file is run directly (not imported by tests)
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n🚀  ExpenseTracker API running on http://localhost:${PORT}`);
    console.log(`\n   POST /api/auth/login     → get your JWT`);
    console.log(`   GET  /api/expenses        → list expenses`);
    console.log(`   GET  /api/admin/users     → admin only (or is it?)\n`);
    console.log(`   Run  npm test             → start the exercises\n`);
  });
}

module.exports = app; // exported for supertest
