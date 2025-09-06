const mongoose = require("mongoose");
const userSchema = mongoose.Schema({
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
  password: { type: String, required: true },
  isEmailVerified: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now },


});

module.exports = mongoose.model("users", userSchema);
