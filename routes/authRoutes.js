// authRoutes.js
const express = require('express');
const router = express.Router();
const {
  register,
  login,
  requestPasswordReset,
  resetPassword
} = require('../controllers/authController');

router.post('/register', register);
router.post('/login', login);
router.post('/requestPasswordReset', requestPasswordReset);
router.post('/resetPassword', resetPassword);

module.exports = router;
