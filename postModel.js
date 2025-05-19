const mongoose = require('mongoose');
require('./userModel'); // just ensures it's registered

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

module.exports = mongoose.model('Post', postSchema); // singular name 'Post'
