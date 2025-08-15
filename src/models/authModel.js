const pool = require('../config/dbConfig');

exports.findByEmail = async (email) => {
  const query = 'SELECT id, password_hash, is_verified, role FROM users WHERE email = $1';
  const result = await pool.query(query, [email]);
  return result.rows[0];
};

exports.createUser = async(first_name, last_name, email, password_hash, address, phone, role, emailTokenHash, tokenExpiresAt) => {
  const query = `
    INSERT INTO users (first_name, last_name, email, password_hash, address, phone, role, created_at, email_token, email_token_expires_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8, $9) 
    RETURNING id
  `;
  result = await pool.query(query, [first_name, last_name, email, password_hash, address, phone, role, emailTokenHash ,tokenExpiresAt]);
  return result.rows[0];
};

exports.createCompany = async (userId, company) => {
  const query = `
    INSERT INTO companies (user_id, name, description, website, created_at)
    VALUES ($1, $2, $3, $4, NOW())
    RETURNING id
  `;
  const result = await pool.query(query, [userId, company.name, company.description, company.website]);
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

exports.insertTokenMail = async (emailTokenHash, tokenExpiresAt, userId) => {
  const query = `
    UPDATE users
    SET email_token = $1, email_token_expires_at = $2
    WHERE id = $3
  `;
  const result = await pool.query(query, [emailTokenHash, tokenExpiresAt, userId]);
  return result.rowCount;
}

exports.findByEmailToken = async (emailTokenHash) => {
  const query = `
    SELECT id FROM users
    WHERE email_token = $1 AND email_token_expires_at > NOW()
  `;
  const result = await pool.query(query, [emailTokenHash]);
  return result.rows[0];
}

exports.deleteEmailToken = async (userId) => {
  const query = `
    UPDATE users
    SET email_token = NULL, email_token_expires_at = NULL
    WHERE id = $1
  `;
  const result = await pool.query(query, [userId]);
  return result.rowCount;
}

exports.setUserAsVerified = async (userId) => {
  const query = `
    UPDATE users
    SET is_verified = TRUE
    WHERE id = $1
  `;
  const result = await pool.query(query, [userId]);
  return result.rowCount;
}

exports.setResetToken = async (userId, resetTokenHash, expiresAt) => {
  const query = `
    UPDATE users
    SET reset_token = $1, reset_token_expires_at = $2
    WHERE id = $3
  `;
  const result = await pool.query(query, [resetTokenHash, expiresAt, userId]);
  return result.rowCount;
}

exports.findByResetToken = async (resetTokenHash) => {
  const query = `
    SELECT id, reset_token_expires_at FROM users
    WHERE reset_token = $1 AND reset_token_expires_at > NOW()
  `;
  const result = await pool.query(query, [resetTokenHash]);
  return result.rows[0];
}

exports.updateUserPassword = async (userId, newPasswordHash) => {
  const query = `
    UPDATE users
    SET password_hash = $1, reset_token = NULL, reset_token_expires_at = NULL
    WHERE id = $2
  `;
  const result = await pool.query(query, [newPasswordHash, userId]);
  return result.rowCount;
}
