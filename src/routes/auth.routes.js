const express = require('express');
const auth = require('../controllers/auth.controller');
const { protect } = require('../middleware/auth.middleware');

const router = express.Router();

// Public routes
router.post('/register', auth.register);
router.post('/login', auth.login);

// Protected routes
router.get('/me', protect, auth.getCurrentUser);
router.put('/profile', protect, auth.updateProfile);
router.put('/change-password', protect, auth.changePassword);

module.exports = router;