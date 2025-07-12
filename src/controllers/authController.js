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
    // Stocker le refreshToken dans la base de données
    //const token = await authService.loginUser(email, password);
    res.status(200).json({ accessToken: accessToken });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};