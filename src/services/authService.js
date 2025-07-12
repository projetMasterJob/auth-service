const authModel = require('../models/authModel');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const authToken = require('../middlewares/authToken');
const mailer = require('../utils/mailer');

exports.registerUser = async (first_name, last_name, email, password, address, phone) => {
  //là il faut faire appel au modèle
  const existingUser = await authModel.findByEmail(email);
  if (existingUser) {
    throw new Error('User already exists');
  }

  const password_hash = await bcrypt.hash(password, 10);
  //ici j'appelle le modèle
  const newUser = await authModel.createUser(first_name, last_name, email, password_hash, address, phone);
  if(!newUser) {
    throw new Error('Error while creating user');
  }
  const emailToken = crypto.randomBytes(32).toString('hex');
  const emailTokenHash = crypto.createHash('sha256').update(emailToken).digest('hex');
  const tokenExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

  const TokenInserted = await authModel.insertTokenMail(emailTokenHash, newUser.id, tokenExpiresAt);
  if(!TokenInserted) {
    throw new Error('Error while inserting email token');
  }
  
  const validationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${emailToken}`;

  try {
    await authModel.insertTokenMail(emailTokenHash, newUser.id, tokenExpiresAt);
  } catch (error) {
    throw new Error('Failed to send validation email');
  }
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

  const accessToken = authToken.generateAccessToken(user);
  const refreshToken = authToken.generateRefreshToken(user);

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
