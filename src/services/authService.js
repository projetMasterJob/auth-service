const authModel = require('../models/authModel');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

exports.registerUser = async (first_name, last_name, email, password, address, phone) => {
  //là il faut faire appel au modèle
  const existingUser = await authModel.findByEmail(email);
  if (existingUser) {
    throw new Error('User already exists');
  }

  const password_hash = await bcrypt.hash(password, 10);
  //ici j'appelle le modèle
  const newUser = authModel.createUser(first_name, last_name, email, password_hash, address, phone);
  if(!newUser) {
    throw new Error('Error while creating user');
  }
  return newUser;
};

exports.loginUser = async (email, password) => {
  const user = await authModel.findByEmail(email);
  if (!user) {
    throw new Error('Cannot find user');
  }

  const validPassword = await bcrypt.compare(password, user.password_hash);
  if (!validPassword) {
    throw new Error('Invalid credentials');
  }

  // Generate access token
  const accessToken = jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '15m' }
  );

  // Generate refresh token
  const refreshToken = jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );

  const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
  const addRefreshToken = await authModel.insertRefreshToken(refreshTokenHash, user.id);

  if (addRefreshToken === 0) {
    throw new Error('Error while updating refresh token');
  }

  return {
    accessToken,
    refreshToken
  };
};
