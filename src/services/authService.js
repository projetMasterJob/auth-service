const authModel = require('../models/authModel');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

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
  const user = authModel.findByEmail(email);
  if (!user) {
    throw new Error('Cannot find user');
  }

  const validPassword = await bcrypt.compare(password, user.passwordHash);
  if (!validPassword) {
    throw new Error('Invalid credentials');
  }

  const token = jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

  return token;
};
