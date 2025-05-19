const jwt = require('jsonwebtoken');
const User = require('./userModel');
require('dotenv').config();

const verifiedToken = async (req, res, next) => {
  const authHeader = req.header('Authorization');

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed token' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET); // Make sure this matches exactly
    req.user = await User.findById(decoded.id).select('-password');
    next();
  } catch (err) {
    console.error('JWT verification error:', err.message);
    res.status(401).json({ error: 'Invalid token' });
  }
};

module.exports = verifiedToken;
