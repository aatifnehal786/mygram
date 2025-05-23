// models/Message.js (or wherever your schema is)
const mongoose = require('mongoose');

const MessageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'users', required: true },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'users', required: true },
  message: { type: String },   // removed `required: true`
  fileUrl: { type: String },
  fileType: { type: String },
  createdAt: { type: Date, default: Date.now }
});



module.exports = mongoose.model('messages', MessageSchema);
