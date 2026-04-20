/**
 * middleware.js — Access Control Middleware
 *
 * Exports two middleware factories:
 *   requirePermission(permission)  → checks role-based permissions
 *   requireOwnership()             → checks resource ownership (IDOR prevention)
 *
 * ─── VULNERABILITY MAP ───────────────────────────────────────────────────────
 *
 *  requirePermission  — The function itself is correct.
 *                       Bugs #4, #5, #6 live in HOW it's applied in app.js
 *                       (missing from routes, wrong permission string, bypassed).
 *
 *  requireOwnership   — BUG #1, #2, #3: This function EXISTS and is correct,
 *                       but it is NOT applied to the relevant routes in app.js.
 *                       Students must identify the missing middleware calls.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 */

const { PERMISSIONS } = require('./roles');
const { findExpenseById } = require('./data');

// ─── PERMISSION CHECK ─────────────────────────────────────────────────────────

/**
 * requirePermission(permission)
 *
 * Middleware factory. Returns a middleware that checks whether the
 * authenticated user's role includes the given permission.
 *
 * Usage:
 *   app.get('/route', verifyToken, requirePermission('expenses:read'), handler)
 *
 * This function is intentionally correct — the bugs are in app.js,
 * where it is misapplied, applied with wrong strings, or skipped entirely.
 */
function requirePermission(permission) {
  return (req, res, next) => {
    const userRole = req.user?.role;
    const allowed = PERMISSIONS[userRole] || [];

    if (!allowed.includes(permission)) {
      return res.status(403).json({
        error: 'Access Denied',
        required: permission,
        yourRole: userRole,
        hint: 'Your role does not have the required permission.',
      });
    }

    next();
  };
}

// ─── OWNERSHIP CHECK ──────────────────────────────────────────────────────────

/**
 * requireOwnership()
 *
 * Middleware factory. Loads the expense from the database and confirms
 * that req.user.userId matches the expense's ownerId.
 *
 * Admins and managers bypass this check (they have non-_own permissions).
 *
 * ⚠️  This middleware is CORRECT but is intentionally NOT wired up
 *     to the vulnerable routes in app.js. That's Bugs #1, #2, and #3.
 *     Students must add it to the appropriate routes.
 *
 * Usage (after fix):
 *   app.get('/api/expenses/:id',
 *     verifyToken,
 *     requirePermission('expenses:read_own'),
 *     requireOwnership(),   // ← students must add this line
 *     getExpenseHandler
 *   )
 */
function requireOwnership() {
  return (req, res, next) => {
    const userRole = req.user?.role;

    // Admins and managers can access any expense — skip ownership check
    if (userRole === 'admin' || userRole === 'manager') {
      return next();
    }

    const expenseId = req.params.id;
    const expense = findExpenseById(expenseId);

    if (!expense) {
      return res.status(404).json({ error: 'Expense not found' });
    }

    if (expense.ownerId !== req.user.userId) {
      return res.status(403).json({
        error: 'Access Denied',
        message: 'You do not own this resource.',
        // CTF flag is included so students know they successfully exploited the bug
        // (this line is removed once the middleware is properly applied)
        flag: expense.flag || null,
      });
    }

    // Attach to request for downstream handlers
    req.expense = expense;
    next();
  };
}

module.exports = { requirePermission, requireOwnership };
