const mongoose = require('mongoose');
// const { boolean } = require('webidl-conversions');

const userSchema = mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  mobile: {
    type: String,
    required: true,
    unique: true,
    validate: {
      validator: function (v) {
        return /^[6-9]\d{9}$/.test(v); // Validates Indian 10-digit mobile numbers
      },
      message: (props) => `${props.value} is not a valid mobile number!`
    }
  },
  profilePic: { type: String },
  chatPin: { type: String, default: null }, // store hashed 4 digit pin
  followers: [{ type: mongoose.Schema.Types.ObjectId, ref: "users" }],
  following: [{ type: mongoose.Schema.Types.ObjectId, ref: "users" }],
  password: { type: String, required: true },
  isEmailVerified: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now },

  // 🔹 new fields for login security
  devices: [
    {
      signature: { type: String }, // combination of ip + user-agent
      addedAt: { type: Date, default: Date.now }
    }
  ],
  pendingOtp: {
    otp: String,
    deviceSignature: String,
    createdAt: Date,
    expiresAt: Date
  }
});



module.exports = mongoose.model('users', userSchema);