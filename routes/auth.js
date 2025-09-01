const express = require('express');
const { signup, login, forgotPassword, resetPassword } = require('../controllers/authController');

const router = express.Router();

router.post('/signup', signup);
router.post('/login', login);
router.post('/forgot-password', forgotPassword);

// Change the reset password route to accept token from the URL
router.post('/reset-password/:token', resetPassword);  // <-- Token is now passed as part of the URL

module.exports = router;
