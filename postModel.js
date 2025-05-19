const mongoose = require('mongoose');
require('./userModel'); // just ensures it's registered

const postSchema = new mongoose.Schema({
  caption: String,
  mediaUrl: String,
  mediaType: { type: String, enum: ['image', 'video'], required: true },
  backgroundMusic: String,
  postedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'users' },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'users' }],
  comments: [{
    text: String,
    commentedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'users' }
  }],
}, { timestamps: true });

module.exports = mongoose.model('posts', postSchema); // singular name 'Post'
