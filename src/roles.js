/**
 * roles.js — Centralized Permission Registry
 *
 * This is the single source of truth for what each role can do.
 * Every permission check in the app flows through here.
 *
 * ┌─────────────┬──────────────────────────────────────────────────────────┐
 * │ Role        │ Permissions                                              │
 * ├─────────────┼──────────────────────────────────────────────────────────┤
 * │ user        │ Read/write their OWN expenses only                       │
 * │ manager     │ Read/write/approve ALL expenses (cannot manage users)    │
 * │ admin       │ Full access including user administration                │
 * └─────────────┴──────────────────────────────────────────────────────────┘
 */

const PERMISSIONS = {
  user: [
    'expenses:read',       // GET /api/expenses            (all expenses - for reporting)
    'expenses:read_own',   // GET /api/expenses/:id        (own only)
    'expenses:write_own',  // POST /api/expenses           (creates for self)
    'expenses:update_own', // PUT /api/expenses/:id        (own only)
    'expenses:delete_own', // DELETE /api/expenses/:id     (own only)
  ],

  manager: [
    'expenses:read',       // GET /api/expenses            (all expenses)
    'expenses:read_own',
    'expenses:write',      // POST /api/expenses           (any user)
    'expenses:write_own',
    'expenses:update',     // PUT /api/expenses/:id        (any expense)
    'expenses:update_own',
    'expenses:approve',    // POST /api/expenses/approve/:id
  ],

  admin: [
    'expenses:read',
    'expenses:read_own',
    'expenses:write',
    'expenses:write_own',
    'expenses:update',
    'expenses:update_own',
    'expenses:delete',     // DELETE /api/expenses/:id     (any expense)
    'expenses:delete_own',
    'expenses:approve',
    'users:read',          // GET /api/admin/users
    'users:admin',         // POST/DELETE /api/admin/users
  ],
};

/**
 * hasPermission(role, permission)
 * Utility for checking permissions outside of middleware (e.g. in tests).
 */
function hasPermission(role, permission) {
  return (PERMISSIONS[role] || []).includes(permission);
}

module.exports = { PERMISSIONS, hasPermission };
