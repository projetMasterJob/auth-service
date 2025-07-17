const authService = require('../services/authService');

exports.register = async (req, res) => {
  try {
    const { first_name, last_name, email, password, address, phone, role } = req.body;
    await authService.registerUser(first_name, last_name, email, password, address, phone, role);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const { accessToken, refreshToken } = await authService.loginUser(email, password);
    res.status(200).json({ accessToken: accessToken });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

// Vérification de l'email
exports.verifyEmail = async (req, res) => {
  try {
    console.log('Received email verification request:', req.query);
    const { token } = req.query;
    await authService.verifyEmailToken(token);
    res.status(200).json({ message: 'Email verified successfully!' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
}

// Envoi de la demande de réinitialisation du mot de passe
exports.requestPasswordReset  = async (req, res) => {
  try {
    const { email } = req.body;
    await authService.requestPasswordReset(email);
    res.status(200).json({ message: 'Password reset request sent successfully!' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

// Réinitialisation du mot de passe
exports.resetPassword = async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    await authService.resetPassword(token, newPassword);
    res.status(200).json({ message: 'Password updated successfully!' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
}