const mongoose = require('mongoose');
const users = require('./userModel'); // 👈 this ensures 'User' model is registered before use

const postSchema = new mongoose.Schema({
  caption: String,
  mediaUrl: String,
  mediaType: { type: String, enum: ['image', 'video'], required: true },
  backgroundMusic: String,
  postedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Users' },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Users' }],
  comments: [{
    text: String,
    commentedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Users' }
  }],
}, { timestamps: true });

module.exports = mongoose.model('Posts', postSchema);
