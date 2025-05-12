//utilise le modèle auth
const authService = require('../services/authService');

exports.register = async (req, res) => {
  try {
    const { email, password } = req.body;
    await authService.registerUser(email, password);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const token = await authService.loginUser(email, password);
    res.status(200).json({ accessToken: token });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};
