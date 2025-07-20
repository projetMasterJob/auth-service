const authModel = require('../models/authModel');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const authToken = require('../middlewares/authToken');
const mailer = require('../utils/mailer');

exports.registerUser = async (first_name, last_name, email, password, address, phone) => {
  //là il faut faire appel au modèle
  const existingUser = await authModel.findByEmail(email);
  if (existingUser) {
    throw new Error('Email already exists');
  }

  const password_hash = await bcrypt.hash(password, 10);
  console.log('Password hashed successfully');

  const emailToken = crypto.randomBytes(32).toString('hex');
  const emailTokenHash = crypto.createHash('sha256').update(emailToken).digest('hex');
  const tokenExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
  console.log('Email token generated:', emailToken);
  
  const newUser = await authModel.createUser(first_name, last_name, email, password_hash, address, phone, emailTokenHash ,tokenExpiresAt);
  if(!newUser) {
    throw new Error('Error while creating user');
  }
  console.log('User created successfully:', newUser);

  // Envoi de l'email de validation
  const validationUrl = `${process.env.URL_AUTH}/verify-email?token=${emailToken}`;
  await mailer.sendValidationEmail(email, validationUrl);
  console.log('Validation email sent to:', email);
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

  console.log('verified user:', user.is_verified);
  if (!user.is_verified) {
    throw new Error('Email not verified');
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

exports.verifyEmailToken = async (token) => {
  console.log('Verifying email token:', token);
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  console.log('Verifying email token:', tokenHash);
  const res = await authModel.findByEmailToken(tokenHash);
  console.log('Token verification result:', res);
  if (!res) {
    throw new Error('Invalid or expired token');
  }

  await authModel.setUserAsVerified(res.id);
  await authModel.deleteEmailToken(res.id);
};

// Demande de réinitialisation du mot de passe
exports.requestPasswordReset  = async (email) => {
  const user = await authModel.findByEmail(email);
  if (!user) return;

  const resetToken = crypto.randomBytes(32).toString('hex');
  const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1h

  await authModel.setResetToken(user.id, resetTokenHash, expiresAt);

  const resetUrl = `${process.env.URL_AUTH}/reset-password?token=${resetToken}`;
  await mailer.sendResetPasswordEmail(email, resetUrl);
}

// Réinitialisation du mot de passe
exports.resetPassword = async (token, newPassword) => {
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const user = await authModel.findByResetToken(tokenHash);

  if (!user || user.reset_password_expires_at < new Date()) {
    throw new Error('Token invalide ou expiré');
  }

  const newHash = await bcrypt.hash(newPassword, 10);
  await authModel.updateUserPassword(user.id, newHash);
  await authModel.clearResetToken(user.id);
}