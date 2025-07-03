const pool = require('../config/dbConfig');

exports.findByEmail = async (email) => {
  const query = 'SELECT id, password_hash FROM users WHERE email = $1';
  const result = await pool.query(query, [email]);
  return result.rows[0];
};

exports.createUser = async(first_name, last_name, email, password_hash, address, phone) => {
  const query = `
    INSERT INTO users (first_name, last_name, email, password_hash, address, phone, role, created_at)
    VALUES ($1, $2, $3, $4, $5, $6, 'user', NOW())
  `;
  result = await pool.query(query, [first_name, last_name, email, password_hash, address, phone]);
  return result.rows[0];
};

exports.insertRefreshToken = async (refreshToken, userId) => {
  const query = `
    UPDATE users
    SET jwt_token = $1
    WHERE id = $2
  `;
  const result = await pool.query(query, [refreshToken, userId]);
  return result.rowCount;
}