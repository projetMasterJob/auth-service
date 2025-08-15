const authModel = require('../models/authModel');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const authToken = require('../middlewares/authToken');
const mailer = require('../utils/mailer');
const validator = require('validator');

exports.registerUser = async (first_name, last_name, email, password, address, phone, role, company) => {
  // Vérification du format de l'email
  if (!validator.isEmail(email)) {
    throw new Error('Adresse email invalide');
  }

  // Vérification de la longueur et de la complexité du mot de passe
  if (typeof password !== "string" || password.length < 6) {
    throw new Error('Le mot de passe doit contenir au moins 6 caractères');
  }
  // Complexité : minuscule, majuscule, chiffre, caractère spécial (exemple)
  const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{6,}$/;
  if (!strongPasswordRegex.test(password)) {
    throw new Error("Le mot de passe doit contenir une majuscule, une minuscule, un chiffre et un caractère spécial");
  }

  // Vérification du rôle
  if (role !== 'user' && role !== 'pro') {
    throw new Error("Rôle invalide (attendu: 'user' ou 'pro')");
  }

  // Vérification des informations de l'entreprise
  if (role === 'pro') {
    if (!company) throw new Error('Les informations entreprise sont requises pour role=pro');
    if (!company.name || !company.description || !company.website) {
      throw new Error('Champs entreprise manquants: name, description et website sont requis');
    }
    if (!validator.isURL(company.website, { require_protocol: true })) {
      throw new Error("URL du site entreprise invalide (ex: https://exemple.com)");
    }
  }

  // Vérifie si l'utilisateur existe déjà
  const existingUser = await authModel.findByEmail(email);
  if (existingUser) {
    throw new Error('Email already exists');
  }

  // Hachage du mot de passe
  const password_hash = await bcrypt.hash(password, 10);

  // Génération du token de validation de l'email
  const emailToken = crypto.randomBytes(32).toString('hex');
  const emailTokenHash = crypto.createHash('sha256').update(emailToken).digest('hex');
  const tokenExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
  
  // Création de l'utilisateur dans la base de données
  const newUser = await authModel.createUser(first_name, last_name, email, password_hash, address, phone, emailTokenHash ,tokenExpiresAt);
  if(!newUser) {
    throw new Error('Error while creating user');
  }
  console.log('User created successfully:', newUser);

  // Enregistrement des informations de l'entreprise
  if(role === 'pro') {
    const companyData = await authModel.createCompany(newUser.id, company);
    if(!companyData) {
      throw new Error('Error while creating company');
    }
    console.log('Company created successfully:', companyData);
  }

  // Envoi de l'email de validation
  const validationUrl = `${process.env.URL_AUTH}/verify-email?token=${emailToken}`;
  await mailer.sendValidationEmail(email, validationUrl);
  console.log('Validation email sent to:', email);
};

exports.loginUser = async (email, password) => {
  // Vérifie si l'utilisateur existe
  const user = await authModel.findByEmail(email);
  if (!user) {
    throw new Error('Cannot find user');
  }

  // Vérifie le mot de passe
  const validPassword = await bcrypt.compare(password, user.password_hash);
  if (!validPassword) {
    throw new Error('Invalid credentials');
  }

  // Vérifie si le compte est vérifié
  if (!user.is_verified) {
    throw new Error('Email not verified');
  }

  // Génération des tokens JWT
  const accessToken = authToken.generateAccessToken(user);
  const refreshToken = authToken.generateRefreshToken(user);

  // Hachage du refresh token pour le stocker en base de données
  const refreshTokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
  const addRefreshToken = await authModel.insertRefreshToken(refreshTokenHash, user.id);

  // Vérification de l'ajout du refresh token
  if (addRefreshToken === 0) {
    throw new Error('Error while updating refresh token');
  }

  return {
    accessToken,
    refreshToken
  };
};

exports.verifyEmailToken = async (token) => {
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const res = await authModel.findByEmailToken(tokenHash);
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
}