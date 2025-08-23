const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

// Route pour l'inscription
router.post('/register', authController.register);

// Route pour la connexion
router.post('/login', authController.login);

// Route pour la vérification de l'email
router.get('/verify-email', authController.verifyEmail);

// Route pour la demande de réinitialisation du mot de passe
router.post('/request-password', authController.requestPasswordReset );

// Route pour la réinitialisation du mot de passe
router.post('/reset-password', authController.resetPassword);

// Route pour le rafraîchissement du token
router.post('/refresh-token', authController.refreshToken);

module.exports = router;