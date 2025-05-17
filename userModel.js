const mongoose = require('mongoose');
// const { boolean } = require('webidl-conversions');

const userSchema =  mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email:    { type: String, required: true, unique: true },
    mobile: {
        type: String,
        required: true,
        unique: true,
        validate: {
          validator: function(v) {
            return /^[6-9]\d{9}$/.test(v);  // Validates Indian 10-digit mobile numbers
          },
          message: props => `${props.value} is not a valid mobile number!`
        }
      },
      profilePic: {
        type: String,
        default: '/uploads/profile_pics/default.png',
      },
      followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Users' }],
      following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Users' }],
      
    password: { type: String, required: true },
    isEmailVerified: {type: Boolean, default: false}
}, { timestamps: true });



module.exports = mongoose.model('Users', userSchema);