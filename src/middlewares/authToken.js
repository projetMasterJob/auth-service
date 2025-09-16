const jwt = require('jsonwebtoken');
const crypto = require('crypto');

exports.generateAccessToken = (user) => {
  return jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '45m' }
  );
};

exports.generateRefreshToken = (user) => {
  const jti = crypto.randomBytes(16).toString('base64url');
  return jwt.sign(
    { sub: user.id, jti, typ: 'refresh' },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '7d', issuer: 'jobazur' }
  );
};

exports.authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

exports.hash = (value) =>
  crypto.createHash('sha256').update(value).digest('hex');

exports.verifyRefreshToken = (token) => {
  try {
    const payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET, { issuer: 'jobazur' });
    return payload;
  } catch (err) {
    console.error('Failed to verify refresh token:', err);
    return null;
  }
};
