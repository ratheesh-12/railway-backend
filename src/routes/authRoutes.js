const express = require('express');
const AccountController = require('../controller/authController');
// const authMiddleware = require('../middleware/authMiddleware'); // JWT authentication middleware
// const roleMiddleware = require('../middleware/roleMiddleware'); // Role-based access control

const router = express.Router();

// =============================================
// PUBLIC ROUTES (No Authentication Required)
// =============================================

// Auth routes
router.post('/register', AccountController.register);
router.post('/login', AccountController.login);

// =============================================
// PROTECTED ROUTES (Authentication Required)
// =============================================

// Profile routes (Any authenticated user)
// router.get('/profile', authMiddleware, AccountController.getProfile);
// router.put('/profile/password/:id', authMiddleware, AccountController.changePassword);

// Account management routes (Admin/Manager only)
// router.get('/accounts', authMiddleware, roleMiddleware(['Admin', 'Manager']), AccountController.getAllAccounts);
// router.get('/accounts/:id', authMiddleware, roleMiddleware(['Admin', 'Manager']), AccountController.getAccountById);
// router.put('/accounts/:id', authMiddleware, roleMiddleware(['Admin', 'Manager']), AccountController.updateAccount);
// router.delete('/accounts/:id', authMiddleware, roleMiddleware(['Admin']), AccountController.deleteAccount);

// Role-based filtering (Admin/Manager only)
// router.get('/accounts/role/:role', authMiddleware, roleMiddleware(['Admin', 'Manager']), AccountController.getAccountsByRole);

// =============================================
// TEMPORARY ROUTES (Remove middleware for testing)
// =============================================

// Profile routes (for testing without middleware)
router.get('/profile', AccountController.getProfile);
router.put('/profile/password/:id', AccountController.changePassword);

// Account management routes (for testing without middleware)
router.get('/accounts', AccountController.getAllAccounts);
router.get('/accounts/:id', AccountController.getAccountById);
router.put('/accounts/:id', AccountController.updateAccount);
router.delete('/accounts/:id', AccountController.deleteAccount);

// Role-based filtering (for testing without middleware)
router.get('/accounts/role/:role', AccountController.getAccountsByRole);

module.exports = router;
