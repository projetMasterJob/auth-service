const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

// Route pour l'inscription
router.post('/register', authController.register);

// Route pour la connexion
router.post('/login', authController.login);

// Route pour la vérification de l'email
router.post('/verify-email', authController.verifyEmail);

module.exports = router;