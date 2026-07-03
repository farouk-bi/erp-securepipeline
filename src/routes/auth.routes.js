const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/user.model');

const JWT_SECRET = process.env.JWT_SECRET || 'changeme-use-vault-in-production';

// POST /api/auth/register
router.post('/register', async (req, res) => {
    try {
        const { username, email, password, role } = req.body;

        // Validation
        if (!username || !email || !password) {
            return res.status(400).json({ error: { message: 'Missing required fields' } });
        }

        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) {
            return res.status(409).json({ error: { message: 'Email already registered' } });
        }

        const user = await User.create({ username, email, password, role: role || 'viewer' });
        
        res.status(201).json({ 
            message: 'User created successfully',
            user: { id: user.id, username: user.username, email: user.email, role: user.role }
        });
    } catch (error) {
        res.status(500).json({ error: { message: error.message } });
    }
});

// POST /api/auth/login
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ where: { email } });
        if (!user || !await user.validatePassword(password)) {
            return res.status(401).json({ error: { message: 'Invalid credentials' } });
        }

        if (!user.isActive) {
            return res.status(403).json({ error: { message: 'Account deactivated' } });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '8h' }
        );

        res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
    } catch (error) {
        res.status(500).json({ error: { message: error.message } });
    }
});

module.exports = router;