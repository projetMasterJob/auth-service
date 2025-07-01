const pool = require('../config/dbConfig');

exports.findByEmail = async (email) => {
  const query = 'SELECT id FROM users WHERE email = $1';
  const result = await pool.query(query, [email]);
  return result.rows[0];
};

exports.createUser = async(first_name, last_name, email, password_harsh, address, phone) => {
  const query = `
    INSERT INTO users (first_name, last_name, email, password_hash, address, phone, role, created_at)
    VALUES ($1, $2, $3, $4, $5, $6, 'user', NOW())
  `;
  result = await pool.query(query, [first_name, last_name, email, password_harsh, address, phone]);
  return result.rows[0];
};