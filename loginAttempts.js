const mongoose = require("mongoose");
const loginAttemptSchema = mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "users" },
  deviceId: String,
  ip: String,
  token: String, // unique approval token
  approved: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now, expires: 600 }, // auto-delete after 10 min
});

module.exports = mongoose.model("loginAttempts", loginAttemptSchema);
