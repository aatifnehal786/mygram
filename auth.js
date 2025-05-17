const jwt = require('jsonwebtoken');
const User = require('./userModel');
require("dotenv").config()

const verifiedToken = async(req,res,next)=>{
    const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_key);
    req.user = await User.findById(decoded.id).select('-password');
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

module.exports = verifiedToken;