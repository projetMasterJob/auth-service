//gère la logique métier à la place du contrôleur
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Simulation d'une base de données en mémoire
const users = []; // [{ id, email, passwordHash }]

exports.registerUser = async (email, password) => {
  const existingUser = users.find(u => u.email === email);
  if (existingUser) {
    throw new Error('User already exists');
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const newUser = { id: users.length + 1, email, passwordHash };
  users.push(newUser);
};

exports.loginUser = async (email, password) => {
  const user = users.find(u => u.email === email);
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
