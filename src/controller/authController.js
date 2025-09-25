const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../config/db'); // Fixed import path

// JWT Secret (since no .env file is used)
const JWT_SECRET = 'railway-backend-secret-key-2024';

class AccountController {
    // Register a new account
    static async register(req, res) {
        const { name, mobile_number, email_id, password, role = 'Worker' } = req.body;

        try {
            // Validate required fields
            if (!name || !mobile_number || !email_id || !password) {
                return res.status(400).json({
                    success: false,
                    message: 'All fields are required: name, mobile_number, email_id, password'
                });
            }

            // Validate role
            if (!['Worker', 'Admin'].includes(role)) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid role. Must be Worker or Admin'
                });
            }

            // Check if email already exists (case-insensitive)
            const emailExists = await db.query(
                'SELECT account_id FROM accounts WHERE LOWER(email_id) = LOWER($1)',
                [email_id]
            );

            if (emailExists.rows.length > 0) {
                return res.status(409).json({
                    success: false,
                    message: 'Email already exists'
                });
            }

            // Check if mobile number already exists
            const mobileExists = await db.query(
                'SELECT account_id FROM accounts WHERE mobile_number = $1',
                [mobile_number]
            );

            if (mobileExists.rows.length > 0) {
                return res.status(409).json({
                    success: false,
                    message: 'Mobile number already exists'
                });
            }

            // Hash password
            const saltRounds = 12;
            const password_hash = await bcrypt.hash(password, saltRounds);

            // Insert new account
            const result = await db.query(
                `INSERT INTO accounts (name, mobile_number, email_id, role, password_hash) 
                 VALUES ($1, $2, $3, $4, $5) 
                 RETURNING account_id, name, mobile_number, email_id, role, created_at`,
                [name, mobile_number, email_id, role, password_hash]
            );

            const newAccount = result.rows[0];

            // Generate JWT token
            const token = jwt.sign(
                { 
                    account_id: newAccount.account_id, 
                    email_id: newAccount.email_id,
                    role: newAccount.role 
                },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.status(201).json({
                success: true,
                message: 'Account created successfully',
                data: {
                    account: newAccount,
                    token
                }
            });

        } catch (error) {
            console.error('Registration error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error during registration'
            });
        }
    }

    // Login to an account
    static async login(req, res) {
        const { email_id, password } = req.body;

        try {
            // Validate required fields
            if (!email_id || !password) {
                return res.status(400).json({
                    success: false,
                    message: 'Email and password are required'
                });
            }

            // Find account by email (case-insensitive)
            const result = await db.query(
                'SELECT * FROM accounts WHERE LOWER(email_id) = LOWER($1)',
                [email_id]
            );

            if (result.rows.length === 0) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid email or password'
                });
            }

            const account = result.rows[0];

            // Verify password
            const isValidPassword = await bcrypt.compare(password, account.password_hash);
            if (!isValidPassword) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid email or password'
                });
            }

            // Generate JWT token
            const token = jwt.sign(
                { 
                    account_id: account.account_id, 
                    email_id: account.email_id,
                    role: account.role 
                },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            // Remove password hash from response
            const { password_hash, ...accountData } = account;

            res.status(200).json({
                success: true,
                message: 'Login successful',
                data: {
                    account: accountData,
                    token
                }
            });

        } catch (error) {
            console.error('Login error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error during login'
            });
        }
    }

    // Get all accounts
    static async getAllAccounts(req, res) {
        try {
            const result = await db.query(
                `SELECT account_id, name, mobile_number, email_id, role, created_at 
                 FROM accounts ORDER BY created_at DESC`
            );

            res.status(200).json({
                success: true,
                message: 'Accounts retrieved successfully',
                data: {
                    accounts: result.rows,
                    count: result.rows.length
                }
            });

        } catch (error) {
            console.error('Get all accounts error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error while retrieving accounts'
            });
        }
    }

    // Get account by ID
    static async getAccountById(req, res) {
        const { id } = req.params;

        try {
            const result = await db.query(
                `SELECT account_id, name, mobile_number, email_id, role, created_at 
                 FROM accounts WHERE account_id = $1`,
                [id]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Account not found'
                });
            }

            res.status(200).json({
                success: true,
                message: 'Account retrieved successfully',
                data: {
                    account: result.rows[0]
                }
            });

        } catch (error) {
            console.error('Get account by ID error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error while retrieving account'
            });
        }
    }

    // Update account
    static async updateAccount(req, res) {
        const { id } = req.params;
        const { name, mobile_number, email_id, role } = req.body;

        try {
            // Check if account exists
            const existingAccount = await db.query(
                'SELECT * FROM accounts WHERE account_id = $1',
                [id]
            );

            if (existingAccount.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Account not found'
                });
            }

            // Validate role if provided
            if (role && !['Worker', 'Admin', 'Manager'].includes(role)) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid role. Must be Worker, Admin, or Manager'
                });
            }

            // Check for email uniqueness if email is being updated
            if (email_id && email_id.toLowerCase() !== existingAccount.rows[0].email_id.toLowerCase()) {
                const emailExists = await db.query(
                    'SELECT account_id FROM accounts WHERE LOWER(email_id) = LOWER($1) AND account_id != $2',
                    [email_id, id]
                );

                if (emailExists.rows.length > 0) {
                    return res.status(409).json({
                        success: false,
                        message: 'Email already exists'
                    });
                }
            }

            // Check for mobile number uniqueness if mobile is being updated
            if (mobile_number && mobile_number !== existingAccount.rows[0].mobile_number) {
                const mobileExists = await db.query(
                    'SELECT account_id FROM accounts WHERE mobile_number = $1 AND account_id != $2',
                    [mobile_number, id]
                );

                if (mobileExists.rows.length > 0) {
                    return res.status(409).json({
                        success: false,
                        message: 'Mobile number already exists'
                    });
                }
            }

            // Build update query dynamically
            const updates = [];
            const values = [];
            let paramCounter = 1;

            if (name) {
                updates.push(`name = $${paramCounter}`);
                values.push(name);
                paramCounter++;
            }

            if (mobile_number) {
                updates.push(`mobile_number = $${paramCounter}`);
                values.push(mobile_number);
                paramCounter++;
            }

            if (email_id) {
                updates.push(`email_id = $${paramCounter}`);
                values.push(email_id);
                paramCounter++;
            }

            if (role) {
                updates.push(`role = $${paramCounter}`);
                values.push(role);
                paramCounter++;
            }

            if (updates.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: 'No fields to update'
                });
            }

            values.push(id);
            const updateQuery = `
                UPDATE accounts 
                SET ${updates.join(', ')} 
                WHERE account_id = $${paramCounter}
                RETURNING account_id, name, mobile_number, email_id, role, created_at
            `;

            const result = await db.query(updateQuery, values);

            res.status(200).json({
                success: true,
                message: 'Account updated successfully',
                data: {
                    account: result.rows[0]
                }
            });

        } catch (error) {
            console.error('Update account error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error while updating account'
            });
        }
    }

    // Delete account
    static async deleteAccount(req, res) {
        const { id } = req.params;

        try {
            const result = await db.query(
                'DELETE FROM accounts WHERE account_id = $1 RETURNING account_id',
                [id]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Account not found'
                });
            }

            res.status(200).json({
                success: true,
                message: 'Account deleted successfully',
                data: {
                    deleted_account_id: result.rows[0].account_id
                }
            });

        } catch (error) {
            console.error('Delete account error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error while deleting account'
            });
        }
    }

    // Change password
    static async changePassword(req, res) {
        const { id } = req.params;
        const { currentPassword, newPassword } = req.body;

        try {
            if (!currentPassword || !newPassword) {
                return res.status(400).json({
                    success: false,
                    message: 'Current password and new password are required'
                });
            }

            // Get current account
            const accountResult = await db.query(
                'SELECT * FROM accounts WHERE account_id = $1',
                [id]
            );

            if (accountResult.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Account not found'
                });
            }

            const account = accountResult.rows[0];

            // Verify current password
            const isValidPassword = await bcrypt.compare(currentPassword, account.password_hash);
            if (!isValidPassword) {
                return res.status(401).json({
                    success: false,
                    message: 'Current password is incorrect'
                });
            }

            // Hash new password
            const saltRounds = 12;
            const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);

            // Update password
            await db.query(
                'UPDATE accounts SET password_hash = $1 WHERE account_id = $2',
                [newPasswordHash, id]
            );

            res.status(200).json({
                success: true,
                message: 'Password changed successfully'
            });

        } catch (error) {
            console.error('Change password error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error while changing password'
            });
        }
    }

    // Get accounts by role
    static async getAccountsByRole(req, res) {
        const { role } = req.params;

        try {
            // Validate role
            if (!['Worker', 'Admin'].includes(role)) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid role. Must be Worker or Admin'
                });
            }

            const result = await db.query(
                `SELECT account_id, name, mobile_number, email_id, role, created_at 
                 FROM accounts WHERE role = $1 ORDER BY created_at DESC`,
                [role]
            );

            res.status(200).json({
                success: true,
                message: `${role} accounts retrieved successfully`,
                data: {
                    accounts: result.rows,
                    count: result.rows.length,
                    role: role
                }
            });

        } catch (error) {
            console.error('Get accounts by role error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error while retrieving accounts by role'
            });
        }
    }

    // Get current user profile (from JWT token)
    static async getProfile(req, res) {
        try {
            const { account_id } = req.user; // This will come from JWT middleware

            const result = await db.query(
                `SELECT account_id, name, mobile_number, email_id, role, created_at 
                 FROM accounts WHERE account_id = $1`,
                [account_id]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Account not found'
                });
            }

            res.status(200).json({
                success: true,
                message: 'Profile retrieved successfully',
                data: {
                    account: result.rows[0]
                }
            });

        } catch (error) {
            console.error('Get profile error:', error);
            res.status(500).json({
                success: false,
                message: 'Internal server error while retrieving profile'
            });
        }
    }
}

module.exports = AccountController;
