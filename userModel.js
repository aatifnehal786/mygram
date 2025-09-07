const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const deviceSchema = new Schema({
  deviceId: { type: String },                // optional: server-generated UUID for the device
  ip: { type: String, required: true },      // IP address at time of login
  userAgent: { type: String, required: true }, // raw user-agent string (or a parsed friendly string)
  name: { type: String },                    // optional friendly name (e.g. "Chrome on Windows")
  authorized: { type: Boolean, default: false }, // true when OTP verified (or first device auto-trusted)
  addedAt: { type: Date, default: Date.now },    // when device was first seen/added
  lastUsed: { type: Date, default: Date.now },   // update on each successful login
  otpHash: { type: String, default: null },      // hashed OTP for verification (DO NOT store plaintext OTP)
  otpExpiresAt: { type: Date, default: null },   // OTP expiry timestamp
  failedOtpAttempts: { type: Number, default: 0 } // count of failed OTP attempts (optional)
});

// Main user schema (keeps your original fields + devices)
const userSchema = new Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  mobile: {
    type: String,
    required: true,
    unique: true,
    validate: {
      validator: function (v) {
        return /^[6-9]\d{9}$/.test(v);
      },
      message: (props) => `${props.value} is not a valid mobile number!`
    }
  },
  profilePic: { type: String },
  chatPin: { type: String, default: null },
  followers: [{ type: mongoose.Schema.Types.ObjectId, ref: "users" }],
  following: [{ type: mongoose.Schema.Types.ObjectId, ref: "users" }],
  password: { type: String, required: true }, // keep hashed passwords
  isEmailVerified: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now },

  // NEW: devices array to store known/authorized devices and OTP metadata
  devices: { type: [deviceSchema], default: [] },

  // OPTIONAL: global setting for trusting device lifetime (0 = never expire)
  // If you want "device trust expiry" policy, set days here (e.g. 90)
  trustedDeviceExpiryDays: { type: Number, default: 0 }
},
{
  timestamps: true // adds createdAt and updatedAt for the user doc
});

module.exports = mongoose.model("users", userSchema);
