/**
 * data.js — In-Memory "Database"
 *
 * This is the lab's fake database. In a real app this would be
 * PostgreSQL, MongoDB, etc. Here it's just plain objects in memory.
 *
 * Reset by restarting the server.
 */

// ─── USERS ────────────────────────────────────────────────────────────────────
// Passwords are stored as bcrypt hashes.
// Plaintext for the lab:
//   alice / password123   → role: user
//   bob   / password123   → role: user
//   carol / password123   → role: manager
//   admin / adminpass     → role: admin
//
// Pre-computed with bcryptjs rounds=10 so startup is instant.

const users = [
  {
    id: 1,
    username: 'alice',
    // plaintext: password123
    password: '$2a$10$zWzHwInzaP24GctqIMUV0u5MD1ZUdfVQ7ZCUwJYgf3EA/zcQQAmPW',
    role: 'user',
    email: 'alice@expensetracker.local',
  },
  {
    id: 2,
    username: 'bob',
    // plaintext: password123
    password: '$2a$10$zWzHwInzaP24GctqIMUV0u5MD1ZUdfVQ7ZCUwJYgf3EA/zcQQAmPW',
    role: 'user',
    email: 'bob@expensetracker.local',
  },
  {
    id: 3,
    username: 'carol',
    // plaintext: password123
    password: '$2a$10$zWzHwInzaP24GctqIMUV0u5MD1ZUdfVQ7ZCUwJYgf3EA/zcQQAmPW',
    role: 'manager',
    email: 'carol@expensetracker.local',
  },
  {
    id: 4,
    username: 'admin',
    // plaintext: adminpass
    password: '$2a$10$Uql0ZyHRNbThWU0pI9dQHehlb/gVEsCFAR7zy/gPfC90ZGbdI/kdK',
    role: 'admin',
    email: 'admin@expensetracker.local',
  },
];

// ─── EXPENSES ─────────────────────────────────────────────────────────────────
// Each expense has an `ownerId` that maps to a user.id.
// This is the field that IDOR checks should validate against.

const expenses = [
  // Alice's expenses (ownerId: 1)
  {
    id: 1,
    ownerId: 1,
    title: 'Team lunch',
    amount: 84.5,
    category: 'meals',
    status: 'pending',
    date: '2024-03-01',
    flag: 'BAC{idor_read_unlocked}',          // flag for bug #1
  },
  {
    id: 2,
    ownerId: 1,
    title: 'Taxi to client office',
    amount: 23.0,
    category: 'travel',
    status: 'approved',
    date: '2024-03-03',
    flag: null,
  },
  {
    id: 3,
    ownerId: 1,
    title: 'SaaS subscription',
    amount: 49.99,
    category: 'software',
    status: 'pending',
    date: '2024-03-05',
    flag: null,
  },

  // Bob's expenses (ownerId: 2)
  {
    id: 4,
    ownerId: 2,
    title: 'Flight to HQ',
    amount: 312.0,
    category: 'travel',
    status: 'pending',
    date: '2024-03-02',
    flag: 'BAC{idor_read_unlocked}',
  },
  {
    id: 5,
    ownerId: 2,
    title: 'Hotel (2 nights)',
    amount: 198.0,
    category: 'accommodation',
    status: 'pending',
    date: '2024-03-04',
    flag: null,
  },

  // Carol's expenses (ownerId: 3)
  {
    id: 6,
    ownerId: 3,
    title: 'Client dinner',
    amount: 230.0,
    category: 'meals',
    status: 'pending',
    date: '2024-03-06',
    flag: null,
  },
  {
    id: 7,
    ownerId: 3,
    title: 'Conference ticket',
    amount: 850.0,
    category: 'training',
    status: 'approved',
    date: '2024-03-07',
    flag: null,
  },
];

// ─── HELPERS ─────────────────────────────────────────────────────────────────

function findUserById(id) {
  return users.find((u) => u.id === id) || null;
}

function findUserByUsername(username) {
  return users.find((u) => u.username === username) || null;
}

function findExpenseById(id) {
  return expenses.find((e) => e.id === parseInt(id, 10)) || null;
}

function findExpensesByOwner(ownerId) {
  return expenses.filter((e) => e.ownerId === ownerId);
}

function updateExpense(id, updates) {
  const idx = expenses.findIndex((e) => e.id === parseInt(id, 10));
  if (idx === -1) return null;
  expenses[idx] = { ...expenses[idx], ...updates };
  return expenses[idx];
}

function deleteExpense(id) {
  const idx = expenses.findIndex((e) => e.id === parseInt(id, 10));
  if (idx === -1) return false;
  expenses.splice(idx, 1);
  return true;
}

function getAllUsers() {
  // Strip password hashes before returning
  return users.map(({ password, ...rest }) => rest);
}

function getAllExpenses() {
  return expenses;
}

module.exports = {
  users,
  expenses,
  findUserById,
  findUserByUsername,
  findExpenseById,
  findExpensesByOwner,
  updateExpense,
  deleteExpense,
  getAllUsers,
  getAllExpenses,
};