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
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    const user = await User.findById(decoded.id).select('-password');

    if (!user) return res.status(401).json({ error: 'Invalid token' });

    const currentDeviceId = req.headers['x-device-id']; // 👈 frontend sends deviceId in header
    const device = user.devices.find(d => d.deviceId === currentDeviceId);

    if (!device || !device.authorized) {
      return res.status(403).json({ error: 'Device removed or unauthorized. Please login again.' });
    }

    req.user = user;
    next();
  } catch (err) {
    console.error('JWT verification error:', err.message);
    res.status(401).json({ error: 'Invalid token' });
  }
};

module.exports = verifiedToken;
