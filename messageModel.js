const mongoose = require('mongoose');
require('./userModel'); 

const messageSchema =  mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'users' },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'users' },
  message: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('messages', messageSchema);
