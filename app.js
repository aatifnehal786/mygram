require('dotenv').config();
const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const cors = require('cors');
const twilio = require('twilio');
const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);
const User = require('./userModel')
const Post = require('./postModel')
// dotenv.config();
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const app = express();
app.use(cors({
  origin: "*", // Allow only your frontend
  credentials: true, // If you're sending cookies or auth headers
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
}));
app.use(express.json());
const auth = require('./auth')
// const multer = require('multer')
const Message = require('./messageModel')
const bcrypt = require('bcryptjs');
// const http = require('http');
// const socketIO = require('socket.io');
const {Server} = require('socket.io');
const {createServer} = require('http');
const jwt = require('jsonwebtoken')
const port = process.env.PORT || 4000;
const useragent = require('express-useragent');
app.use(useragent.express());
 
// Serve uploaded images statically
// app.use('/uploads', express.static('uploads'));
console.log("SID:", process.env.TWILIO_SID);
console.log("AUTH:", process.env.TWILIO_AUTH_TOKEN);
console.log("VERIFY:", process.env.TWILIO_VERIFY_SID);


// Download the helper library from https://www.twilio.com/docs/node/install
// const twilio = require("twilio"); // Or, for ESM: import twilio from "twilio";

// Find your Account SID and Auth Token at twilio.com/console
// and set the environment variables. See http://twil.io/secure

// Download the helper library from https://www.twilio.com/docs/node/install
 // Or, for ESM: import twilio from "twilio";

// Find your Account SID and Auth Token at twilio.com/console
// and set the environment variables. See http://twil.io/secure



mongoose.connect(process.env.MONGO_URL)
    .then(() => console.log(`Database connection successful, ${process.env.MONGO_URL}`))
    .catch((err) => console.log(err));


// Email transporter
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.MY_GMAIL,
        pass: process.env.GMAIL_PASSWORD
    }
});



const otpStorage = {};




app.post("/login", async (req, res) => {
  const { loginId, password, deviceId } = req.body;
  const ipAddress = req.ip;

  try {
    const user = await User.findOne({
      $or: [{ email: loginId }, { username: loginId }, { mobile: loginId }],
    });

    if (!user) return res.status(404).json({ message: "User not found" });
    if (!user.isEmailVerified)
      return res.status(403).json({ message: "Email not verified" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "Incorrect password" });

 
     const ua = req.useragent;

    // Check if device exists
    const existingDevice = user.devices.find(d => d.deviceId === deviceId);

    if (existingDevice) {
      if (existingDevice.authorized) {
        // ✅ Device authorized → normal login
        const token = jwt.sign(
          { email: user.email, id: user._id },
          process.env.JWT_SECRET_KEY,
          { expiresIn: "7d" }
        );

        return res.status(200).json({
          token,
          message: "Login successful",
          userid: user._id,
          name: user.username,
        });
      } else {
        // ⚠️ Device exists but not authorized → send OTP
        // generate OTP
        const otp = crypto.randomInt(100000, 999999).toString();
        otpStorage[user.email] = { otp, expiresAt: Date.now() + 10 * 60 * 1000 };

        // send email (nodemailer)
        await transporter.sendMail({
          from: `"Instagram" <${process.env.MY_GMAIL}>`,
          to: user.email,
          subject: "Your OTP Code",
          text: `Your OTP code is ${otp}. It will expire in 10 minutes.`,
        });

        return res.status(200).json({
          otpRequired: true,
          message: "New device detected. OTP sent to email.",
          email: user.email,
        });
      }
    } else {
      // ⚡ New device → add device with authorized: false and send OTP
     

user.devices.push({
      deviceId: deviceId, // use frontend deviceId
      ip: ipAddress,
      userAgent: ua.source,
      authorized: false,
      addedAt: new Date(),
      lastUsed: new Date(),
    });

      const otp = crypto.randomInt(100000, 999999).toString();
      otpStorage[user.email] = { otp, expiresAt: Date.now() + 10 * 60 * 1000 };

      await transporter.sendMail({
        from: `"Instagram" <${process.env.MY_GMAIL}>`,
        to: user.email,
        subject: "Your OTP Code",
        text: `Your OTP code is ${otp}. It will expire in 10 minutes.`,
      });

      return res.status(200).json({
        otpRequired: true,
        message: "New device detected. OTP sent to email.",
        email: user.email,
      });
    }
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// VERIFICATION FOR DEVICE



app.post("/verify-device-otp", async (req, res) => {
  const { email, otp, deviceId } = req.body;
  console.log("Verify request:", deviceId, email, otp);

  if (!email || !otp || !deviceId) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  const storedOtp = otpStorage[email];
  if (!storedOtp || storedOtp.otp !== otp || storedOtp.expiresAt < Date.now()) {
    return res.status(400).json({ message: "Invalid or expired OTP" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const ua = req.useragent

    // ✅ Check if device already exists
    const existingDevice = user.devices.find(d => d.deviceId === deviceId);

    if (existingDevice) {
      existingDevice.ip = req.ip;
      existingDevice.userAgent = userAgentStr;
      existingDevice.authorized = true;
      existingDevice.addedAt = new Date();
    } else {
      user.devices.push({
        deviceId,
        ip: req.ip,
        userAgent: ua.source,
        authorized: true,
        addedAt: new Date(),
      });
    }

    await user.save();

    delete otpStorage[email]; // clear OTP

    const token = jwt.sign(
      { email: user.email, id: user._id },
      process.env.JWT_SECRET_KEY,
      { expiresIn: "7d" }
    );

    res.status(200).json({
      token,
      message: "Device verified & login successful",
      userid: user._id,
      name: user.username,
    });
  } catch (err) {
    console.error("OTP verification error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get all devices
app.get("/devices", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select("devices");
    if (!user) return res.status(404).json({ message: "User not found" });

    res.json({ devices: user.devices });
  } catch (err) {
    console.error("Fetch devices error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Remove one device
// Remove one device
app.delete("/devices/:deviceId", auth, async (req, res) => {
  try {
    const { deviceId } = req.params;
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ message: "User not found" });

    const originalLength = user.devices.length;
    user.devices = user.devices.filter(d => d.deviceId !== deviceId);

    if (user.devices.length === originalLength) {
      return res.status(404).json({ message: "Device not found" });
    }

    await user.save(); // ⚡ important: saves the updated array

    res.json({ message: "Device removed", devices: user.devices });
  } catch (err) {
    console.error("Remove device error:", err);
    res.status(500).json({ message: "Server error" });
  }
});




// Remove all other devices except current
app.delete("/devices/remove-others/:currentDeviceId", auth, async (req, res) => {
  try {
    const { currentDeviceId } = req.params;
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ message: "User not found" });
    

    user.devices = user.devices.filter(d => d.deviceId === currentDeviceId);
    await user.save();

    res.json({ message: "Removed all other devices", devices: user.devices });
  } catch (err) {
    console.error("Remove other devices error:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// user sign up endpoint 

app.post("/signup",async (req,res)=>{

    let { username, email, password, mobile } = req.body;
    const olduser = await User.findOne({ email: email });
    if (olduser) return res.status(403).send({ message: "User already registered" });

    const oldUsername = await User.findOne({username:username})
    if(oldUsername) return res.status(403).json({message:"Choose Different Username, Username already exists"})
    

     const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: "Invalid email format" });
  }
    const passwordRegex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  if (!passwordRegex.test(password)) {
    return res.status(401).json({
      message:
        "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character",
    });
  }

    try {
        const salt = await bcrypt.genSalt(10);
        password = await bcrypt.hash(password, salt);
        const user = await User.create({ username, email, password, mobile });
        res.status(201).send({ user, message: "User registered" });
    } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Some problem" });
    }
})








// 




 
// send-otp endpoint

app.post("/send-otp", async (req, res) => {
  const { mobile } = req.body;

  try {
    const verification = await client.verify.v2.services(process.env.TWILIO_VERIFY_SID)
      .verifications.create({ to: `+91${mobile}`, channel: 'sms' });

    res.json({ message: 'OTP sent', status: verification.status });
  } catch (err) {
    console.error("OTP Send Error:", err.message); // log error for debugging
    res.status(500).json({ error: err.message });
  }
});


app.post("/verify-otp", async (req, res) => {
  const { mobile, otp } = req.body;

  try {
    const verificationCheck = await client.verify.v2.services(process.env.TWILIO_VERIFY_SID)
      .verificationChecks.create({ to: `+91${mobile}`, code:otp });

    if (verificationCheck.status === 'approved') {
      res.json({ message: 'OTP verified successfully' });
    } else {
      res.status(400).json({ error: 'Invalid or expired OTP' });
    }
  } catch (err) {
    console.error("OTP Verify Error:", err.message); // log error for debugging
    res.status(500).json({ error: err.message });
  }
});


// Send OTP
app.post("/send-email-otp", async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required" });

    const otp = crypto.randomInt(100000, 999999).toString();
    otpStorage[email] = { otp, expiresAt: Date.now() + 10 * 60 * 1000 };
    

    try {
        await transporter.sendMail({
            from: `"Instagram" <${process.env.MY_GMAIL}>`,
            to: email,
            subject: "Your OTP Code",
            text: `Your OTP code is ${otp}. It will expire in 5 minutes.`,
        });
        res.json({ message: "OTP sent successfully" });
        console.log(otpStorage)
        
    } catch (err) {
        console.error("Error sending email:", err);
        res.status(500).json({ error: "Failed to send OTP" });
    }
});

// Verify OTP
app.post("/verify-email-otp", async (req, res) => {
  const email = req.body.email?.toLowerCase();
  const otp = req.body.otp?.toString();

  const storedData = otpStorage[email];
  if (!storedData || storedData.otp !== otp || storedData.expiresAt < Date.now()) {
      return res.status(400).json({ error: "Invalid or expired OTP" });
  }

  try {
      await User.updateOne({ email }, { isEmailVerified: true });
      delete otpStorage[email];
      res.json({ message: "OTP verified successfully" });
  } catch (err) {
      console.error("Error verifying OTP:", err);
      res.status(500).json({ error: "Failed to verify OTP" });
  }
});



// Multer setup
// middleware/upload.js
const multer = require("multer");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const cloudinary = require("./cloudinaryconfig");

const profilePicStorage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "profile_pics",
    allowed_formats: ["jpg", "jpeg", "png"],
    transformation: [{ width: 300, height: 300, crop: "limit" }],
  },
});



const uploadProfilePic = multer({ storage: profilePicStorage });






// Profile pic upload route
app.post('/user/profile-pic', auth, uploadProfilePic.single('profilePic'), async (req, res) => {
  try {
    if (!req.file || !req.file.path) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    console.log("Authenticated user:", req.user);

    const userId = req.user._id;
    const profilePicUrl = req.file.path; // Cloudinary URL

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { profilePic: profilePicUrl },
      { new: true }
    );

    res.status(200).json({
      message: 'Profile picture updated',
      profilePic: profilePicUrl,
      user: updatedUser
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update profile picture' });
  }
});
// Forgot Password
app.post("/forgot-password", async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required" });
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: "Invalid email format" });
  }
    let user = await User.findOne({email})
    if(!user){
      return res.status(404).json({message:"User not Registered With This Email"})
    }

    const otp = crypto.randomInt(100000, 999999).toString();
    otpStorage[email] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 };

    try {
        await transporter.sendMail({
            from: `"Intagram Forgot Password Recovery" <${process.env.MY_GMAIL}>`,
            to: email,
            subject: "Your OTP Code",
            text: `Your OTP code is ${otp}. It will expire in 5 minutes.`,
        });
        res.json({ message: "OTP sent successfully" });
    } catch (err) {
        console.error("Error sending email:", err);
        res.status(500).json({ error: "Failed to send OTP" });
    }
});

// Reset Password
app.post("/reset-password", async (req, res) => {
    const { email, newPass, otp } = req.body;
    const storedData = otpStorage[email];

    if (!email || !otp || !newPass) return res.status(400).json({ error: "Email, OTP, and new password are required" });
    if (!storedData || storedData.otp !== otp || storedData.expiresAt < Date.now()) {
        return res.status(400).json({ error: "Invalid or expired OTP" });
    }

      const passwordRegex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  if (!passwordRegex.test(newPass)) {
    return res.status(401).json({
      message:
        "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character",
    });
  }

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: "User not found" });

        const isSame = await bcrypt.compare(newPass, user.password);
        if (isSame) return res.status(400).json({ error: "New password cannot be the same as the current password" });

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPass, salt);
        await user.save();
        delete otpStorage[email];
        res.status(200).json({ message: "Password reset successfully" });
    } catch (err) {
        console.error("Error resetting password:", err);
        res.status(500).json({ message: "Some problem occurred" });
    }
});

// upload.js (or uploads.js)
// const multer = require('multer');
// const { CloudinaryStorage } = require('multer-storage-cloudinary');
// const cloudinary = require('./cloudinaryconfig');
// const path = require('path');

const storage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => {
    const ext = path.extname(file.originalname).toLowerCase();
    let folder = 'posts';

    if (file.fieldname === 'backgroundMusic') folder = 'music';

    return {
      folder,
      resource_type: 'auto', // Auto-detect image/audio/video
      public_id: `${Date.now()}-${file.originalname.split('.')[0]}`,
    };
  },
});

const upload = multer({ storage });





// Post Creation Endpoint
app.post(
  "/create-post",
  auth,
  upload.fields([
    { name: "image", maxCount: 1 },
    { name: "backgroundMusic", maxCount: 1 }
  ]),
  async (req, res) => {
    try {
      const { caption, mediaType } = req.body;

      const imageFile = req.files?.image?.[0];
      const musicFile = req.files?.backgroundMusic?.[0];

      if (!imageFile) {
        return res.status(400).json({ error: "Media file is required." });
      }

      const post = await Post.create({
        caption,
        mediaType,
        mediaUrl: imageFile.path, // Cloudinary URL
        backgroundMusic: mediaType === "image" && musicFile ? musicFile.path : null, // Cloudinary URL
        postedBy: req.user.id
      });

      res.status(201).json({ post });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: err.message });
    }
  }
);

// fetch posts
app.get("/allposts",auth,async(req,res)=>{
  try {
    res.set('Cache-Control', 'no-store')
    const posts = await Post.find()
      .populate('postedBy', '_id name')
      .populate('comments.commentedBy', '_id name')
      .sort('-createdAt');

    res.status(200).json(posts);
  } catch (err) {
    console.error('Error fetching posts:', err);
    res.status(500).json({ error: 'Failed to fetch posts' });
  }
})
// likes Post

app.put("/like/:postid",auth, async (req,res)=>{
    const userId = req.user._id;
  const { postid } = req.params;
  const post = await Post.findByIdAndUpdate(
    postid,
    { $addToSet: { likes: userId } },
    { new: true }
  );
  res.json(post);
})

// unlike Post

app.put("/unlike/:postid",auth, async (req,res)=>{
    const userId = req.user.id;
    const { postid } = req.params;
    const post = await Post.findByIdAndUpdate(
      postid,
      { $pull: { likes: userId } },
      { new: true }
    );
    res.json(post);
})

// Comment

app.post("/comment/:postid",auth,async (req,res)=>{
    const userId = req.user._id;
  const { postid } = req.params;
  const { text } = req.body;

  const post = await Post.findByIdAndUpdate(
    postid,
    { $push: { comments: { text, commentedBy: userId } } },
    { new: true }
  ).populate('comments.commentedBy', 'username');

  res.json(post);
})

// FOLLOW

app.put("/follow/:targetUserId", auth, async (req, res) => {
  const currentUserId = req.user._id;
  const { targetUserId } = req.params;

  if (!targetUserId) {
    return res.status(400).json({ error: "Missing userId to follow." });
  }

  await User.findByIdAndUpdate(currentUserId, { $addToSet: { following: targetUserId } });
  await User.findByIdAndUpdate(targetUserId, { $addToSet: { followers: currentUserId } });

  res.json({ message: "Followed" });
});
// UNFOLLOW

app.put("/unfollow/:targetUserId", auth, async (req, res) => {
  const currentUserId = req.user._id;
  const { targetUserId } = req.params;

  if (!targetUserId) {
    return res.status(400).json({ error: "Missing userId to unfollow." });
  }

  await User.findByIdAndUpdate(currentUserId, { $pull: { following: targetUserId } });
  await User.findByIdAndUpdate(targetUserId, { $pull: { followers: currentUserId } });

  res.json({ message: "Unfollowed" });
});
// Get follow status
app.get("/follow-status/:targetUserId", auth, async (req, res) => {
  const currentUserId = req.user._id;
  const { targetUserId } = req.params;

  const currentUser = await User.findById(currentUserId);

  if (!currentUser) {
    return res.status(404).json({ error: "User not found" });
  }

  const isFollowing = currentUser.following.includes(targetUserId);

  res.json({ isFollowing });
});

// NUMBER OF POSTS LIKES FOLLOWERS COUNTS ENDPOINT

app.delete("/delete-post/:id",auth,async (req,res)=>{
  const {id} = req.params;
  console.log(id)

  const post = await Post.findByIdAndDelete(id)
  if(post){
    res.status(200).json({message:"Post deleted Successfully"},post)
  }
})

app.get('/users/:id/stats',auth, async (req, res) => {
    try {
      const userId = req.params.id;
  
      const user = await User.findById(userId)
        .populate('followers', 'username')
        .populate('following', 'username');
  
      const posts = await Post.find({ postedBy: userId });
      const postCount = posts.length;
      const totalLikes = posts.reduce((acc, post) => acc + post.likes.length, 0);
  
      res.json({
        username: user.username,
        followersCount: user.followers.length,
        followingCount: user.following.length,
        postsCount: postCount,
        likesReceived: totalLikes,
         profilePic: user.profilePic, // <-- add this
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
app.get("/allusers1", auth, async (req, res) => {
  try {
    const loggedInUserId = req.user._id; // assuming `auth` middleware attaches the user object
    const users = await User.find({ _id: { $ne: loggedInUserId } }); // exclude current user
    res.status(200).json(users);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error while fetching users" });
  }
});
app.get("/allusers2", auth, async (req, res) => {
  try {
     
    const users = await User.find(); // exclude current user
    res.status(200).json(users);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error while fetching users" });
  }
});

app.get("/allPosts", async (req, res) => {
  try {
    const allPosts = await Post.find()
    
    
    res.status(200).json(allPosts);
  } catch (err) {
    console.error("Error fetching posts:", err);
    res.status(500).json({ error: "Failed to fetch posts" });
  }
});

// const cloudinary = require('../utils/cloudinary');
// const multer = require('multer');
const streamifier = require('streamifier');
const upload3 = multer();

app.post('/upload/chat', upload3.single('file'), async (req, res) => {
  try {
    const mimeType = req.file.mimetype;
    const mainType = mimeType.split('/')[0];

    // Determine correct resource_type
    let resourceType = 'auto'; // default
    if (
      mimeType === 'application/pdf' ||
      mimeType === 'application/msword' ||
      mimeType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ||
      mimeType.startsWith('text/')
    ) {
      resourceType = 'raw';
        // for documents
    }

    const streamUpload = () =>
      new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          {
            resource_type: resourceType,
            folder: 'chat_files',
            type: 'upload', // ensure public access
          },
          (error, result) => {
            if (result) resolve(result);
            else reject(error);
          }
        );
        streamifier.createReadStream(req.file.buffer).pipe(stream);
      });

    const result = await streamUpload();

    res.json({ fileUrl: result.secure_url, fileType: mimeType });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Upload failed' });
  }
});


// followers list
app.get("/followers/:userId", auth, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).populate('followers', '_id username profilePic lastSeen');
    if (!user) return res.status(404).json({ message: 'User not found' });

    const onlineUserIds = Array.from(onlineUsers.keys());

    const followersWithOnlineStatus = user.followers.map(f => ({
      _id: f._id,
      username: f.username,
      profilePic: f.profilePic,
      lastSeen: f.lastSeen,
      isOnline: onlineUserIds.includes(f._id.toString())
    }));

    res.json({ followers: followersWithOnlineStatus });
  } catch (err) {
    console.error('Error fetching followers:', err);
    res.status(500).json({ message: 'Server error' });
  }
});


app.delete("/delete-chat",auth,async (req,res)=>{

   try {
    const { messageIds } = req.body;


    const result = await Message.deleteMany({ _id: { $in: messageIds } });

    
    if (!result) {
      return res.status(400).json({ message: 'No message IDs provided' });
    }

    res.status(200).json({
      message: `${result.deletedCount} message(s) deleted successfully.`,
    });
  } catch (error) {
    console.error('Error deleting messages:', error);
    res.status(500).json({ message: 'Server error while deleting messages' });
  }
})

// Socket setup




const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  }
});

let onlineUsers = new Map(); // userId => Set of socket IDs

io.on('connection', (socket) => {
  console.log('New socket connection:', socket.id);

  socket.on('join', (userId) => {
    if (!onlineUsers.has(userId)) {
      onlineUsers.set(userId, new Set());
    }
    onlineUsers.get(userId).add(socket.id);
    io.emit('onlineUsers', Array.from(onlineUsers.keys()));
  });

  socket.on('sendMessage', async ({ senderId, receiverId, message, fileUrl, fileType, isForwarded }) => {
    try {
      const sender = await User.findById(senderId);
      const receiver = await User.findById(receiverId);
      if (!sender || !receiver) return;

      const newMsg = await Message.create({
        sender: senderId,
        receiver: receiverId,
        message: message || '',
        fileUrl: fileUrl || null,
        fileType: fileType || null,
        isForwarded: isForwarded || false,
        createdAt: new Date()
      });

      const sendToUserSockets = (userId, msg) => {
        const sockets = onlineUsers.get(userId);
        if (sockets) {
          sockets.forEach(sockId => io.to(sockId).emit('receiveMessage', msg));
        }
      };

      sendToUserSockets(senderId, newMsg);
      sendToUserSockets(receiverId, newMsg);
    } catch (err) {
      console.error("Error in sendMessage:", err);
    }
  });

  socket.on('getOnlineStatus', (userId, cb) => {
    cb(onlineUsers.has(userId));
  });

  // ✅ Video/Audio Call Signaling Events
socket.on('call-user', ({ from, to, offer }) => {
  // console.log('📤 Calling user', to, 'from', from, 'type:', type);
  const targetSockets = onlineUsers.get(to);
  if (targetSockets) {
    targetSockets.forEach(sockId =>
      io.to(sockId).emit('incoming-call', { from, offer }) // ✅ include type
    );
  }
});


  socket.on('answer-call', ({ to, answer }) => {
    const targetSockets = onlineUsers.get(to);
    if (targetSockets) {
      targetSockets.forEach(sockId =>
        io.to(sockId).emit('call-answered', { answer })
      );
    }
  });

  socket.on('ice-candidate', ({ to, candidate }) => {
    const targetSockets = onlineUsers.get(to);
    if (targetSockets) {
      targetSockets.forEach(sockId =>
        io.to(sockId).emit('ice-candidate', { candidate })
      );
    }
  });

  socket.on('end-call', ({ to }) => {
    const targetSockets = onlineUsers.get(to);
    if (targetSockets) {
      targetSockets.forEach(sockId =>
        io.to(sockId).emit('call-ended')
      );
    }
  });

  socket.on('reject-call', ({ to }) => {
  const targetSockets = onlineUsers.get(to);
  if (targetSockets) {
    targetSockets.forEach(sockId =>
      io.to(sockId).emit('call-rejected')  // this should match frontend listener
    );
  }
});


  socket.on('disconnect', async () => {
    for (let [userId, socketSet] of onlineUsers.entries()) {
      socketSet.delete(socket.id);
      if (socketSet.size === 0) {
        onlineUsers.delete(userId);
        try {
          await User.findByIdAndUpdate(userId, { lastSeen: new Date() });
        } catch (err) {
          console.error('Failed to update last seen:', err);
        }
      }
    }
    io.emit('onlineUsers', Array.from(onlineUsers.keys()));
    console.log('Socket disconnected:', socket.id);
  });
});

// module.exports = server;


// chat endpoint 

app.get("/chat/:userId", auth, async (req, res) => {
  try {
    const currentUserId = req.user.id;
    const targetUserId = req.params.userId;

    // Check if both users exist
    const sender = await User.findById(currentUserId);
    const receiver = await User.findById(targetUserId);

    if (!sender || !receiver) {
      return res.status(404).json({ error: 'User not found' });
    }

    // ❌ REMOVE mutual follower check

    // Get chat messages between the two users
    const messages = await Message.find({
      $or: [
        { sender: currentUserId, receiver: targetUserId },
        { sender: targetUserId, receiver: currentUserId }
      ]
    }).sort({ createdAt: 1 });

    return res.status(200).json(messages);
  } catch (err) {
    console.error('Error in /chat/:targetUserId:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.get('/search-users', auth, async (req, res) => {
  const query = req.query.q;
  const onlineUserIds = Array.from(onlineUsers.keys());

  try {
    const users = await User.find({
      $or: [
        { name: { $regex: query, $options: 'i' } },
        { username: { $regex: query, $options: 'i' } }
      ]
    }).select('_id name username profilePic lastSeen'); // add lastSeen here

    // Enhance users with isOnline field
    const enhancedUsers = users.map(user => ({
      _id: user._id,
      name: user.name,
      username: user.username,
      profilePic: user.profilePic,
      lastSeen: user.lastSeen,
      isOnline: onlineUserIds.includes(user._id.toString())
    }));

    res.status(200).json(enhancedUsers);
  } catch (err) {
    console.error('User search failed:', err);
    res.status(500).json({ error: 'Server error' });
  }
});



app.get('/chat-list', auth, async (req, res) => {
  try {
    const userId = req.user.id;
    console.log('Fetching chats for user:', userId);

    const messages = await Message.find({
      $or: [{ sender: userId }, { receiver: userId }]
    }).populate('sender receiver', 'name username profilePic');

    console.log('Messages found:', messages.length);

    const uniqueUsers = new Map();

    messages.forEach(msg => {
      if (!msg.sender || !msg.receiver) return; // Skip if either is null

      const partner =
        msg.sender._id.toString() === userId
          ? msg.receiver
          : msg.sender;

      if (partner && partner._id) {
        uniqueUsers.set(partner._id.toString(), partner);
      }
    });

    const usersArray = Array.from(uniqueUsers.values());
    console.log('Unique chat partners:', usersArray.length);

    res.status(200).json(usersArray);
  } catch (err) {
    console.error('Chat list error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});


app.post("/chat/forward", async (req, res) => {
  const { senderId, receiverId, message, fileUrl, fileType, isForwarded } = req.body;

  try {
    const newMsg = await Message.create({
      sender: senderId,
      receiver: receiverId,
      message: message || '',
      fileUrl: fileUrl || null,
      fileType: fileType || null,
      isForwarded: isForwarded || false,
      createdAt: new Date()
    });



    res.json(newMsg);

        
  
  } catch (err) {
    console.error("Error in /chat/forward:", err);
    res.status(500).json({ error: "Failed to forward message" });
  }
});



app.post("/set-chat-pin", async (req, res) => {
  try {
    const { userId, pin } = req.body;
    if (!/^\d{4}$/.test(pin)) return res.status(400).json({ msg: "PIN must be 4 digits" });

    const hashedPin = await bcrypt.hash(pin, 10);
    await User.findByIdAndUpdate(userId, { chatPin: hashedPin });

    res.json({ msg: "Chat PIN set successfully" });
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
});

app.post("/verify-chat-pin", async (req, res) => {
  const { userId, pin } = req.body;

  if (!userId || !pin) return res.status(400).json({ message: "User ID and PIN are required" });

  const user = await User.findById(userId);
  if (!user || !user.chatPin) return res.status(404).json({ message: "PIN not set" });

  const isMatch = await bcrypt.compare(pin, user.chatPin);
  if (!isMatch) return res.status(400).json({ message: "Invalid PIN" });

  res.json({ message: "PIN verified successfully" });
});


app.post("/check-chat-pin",auth,async(req,res)=>{
   try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ msg: "User ID is required" });
    }

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ msg: "User not found" });
    }

    if (user.chatPin) {
      return res.json({ hasPin: true, msg: "Chat PIN already set" });
    }

    res.json({ hasPin: false, msg: "No PIN set yet" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Server error" });
  }
})




// In-memory OTP storage (you can move this to DB if needed)
const chatPinOtpStorage = {};

// POST /forgot-chat-pin
app.post("/forgot-chat-pin", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email is required" });

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: "Invalid email format" });
  }

  // Check if user exists
  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: "User not registered with this email" });

  // Generate OTP
  const otp = crypto.randomInt(100000, 999999).toString();

  // Save OTP in memory with expiry
  chatPinOtpStorage[email] = {
    otp,
    expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes
    userId: user._id,
  };

  try {
    // Send OTP email
    await transporter.sendMail({
      from: `"MyGram Chat PIN Recovery" <${process.env.MY_GMAIL}>`,
      to: email,
      subject: "Your Chat PIN OTP",
      text: `Your OTP to reset your chat PIN is ${otp}. It will expire in 5 minutes.`,
    });

    res.json({ message: "OTP sent successfully" });
  } catch (err) {
    console.error("Error sending OTP email:", err);
    res.status(500).json({ error: "Failed to send OTP" });
  }
});


// POST /reset-chat-pin


app.post("/reset-chat-pin", async (req, res) => {
  const { email, otp, newPin } = req.body;

  if (!email || !otp || !newPin)
    return res.status(400).json({ message: "All fields are required" });

  const record = chatPinOtpStorage[email];
  if (!record)
    return res.status(400).json({ message: "No OTP requested for this email" });

  if (record.otp !== otp) return res.status(400).json({ message: "Invalid OTP" });
  if (Date.now() > record.expiresAt) return res.status(400).json({ message: "OTP expired" });

  // Fetch user using email
  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: "User not found" });

  // 🔑 Hash the new PIN before saving
  const hashedPin = await bcrypt.hash(newPin.toString(), 10);
  user.chatPin = hashedPin;
  await user.save();

  delete chatPinOtpStorage[email];

  res.json({ message: "Chat PIN reset successfully" });
});



// removeChatPin.js (controller or directly in your routes file)
app.post("/remove-chat-pin", async (req, res) => {
  try {
    const { userId } = req.body;

    // assuming you store pin in User collection
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    user.chatPin = null; // remove chat pin
    await user.save();

    res.json({ message: "Chat lock removed successfully" });
  } catch (err) {
    res.status(500).json({ message: "Error removing chat lock", error: err.message });
  }
});


server.listen(port, () => {
    console.log(`Server is up and running on port ${port}`);
});
