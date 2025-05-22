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
app.use(cors());
app.use(express.json());
const auth = require('./auth')
// const multer = require('multer')
const Message = require('./messageModel')
const bcrypt = require('bcryptjs');
const http = require('http');
const socketIO = require('socket.io');
const jwt = require('jsonwebtoken')
const port = process.env.PORT || 4000;
// Serve uploaded images statically
// app.use('/uploads', express.static('uploads'));
console.log("SID:", process.env.TWILIO_SID);
console.log("AUTH:", process.env.TWILIO_AUTH_TOKEN);
console.log("VERIFY:", process.env.TWILIO_VERIFY_SID);


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


// user sign up endpoint 

app.post("/signup",async (req,res)=>{

    let { username, email, password, mobile } = req.body;
    const olduser = await User.findOne({ email: email });
    if (olduser) return res.status(403).send({ message: "User already registered" });

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

// login

app.post("/login", async (req, res) => {
    const { loginId, password } = req.body;

    try {
         const user = await User.findOne({
      $or: [
        { email: loginId },
        { username: loginId },
        { mobile: loginId },
      ],
    });
        if (!user) return res.status(404).send({ message: "User not found" });
        if (!user.isEmailVerified) {
            return res.status(403).json({ message: "Email not verified. Please verify your email to login." });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: "Incorrect password" });

        const token = jwt.sign({ email: user.email, id: user._id }, process.env.JWT_SECRET_KEY, { expiresIn: "1h" });

        res.status(200).send({
            token,
            message: "Login successful",
            userid: user._id,
            name: user.name,
        });
    } catch (err) {
        console.error("Unexpected server error:", err);
        res.status(500).json({ message: "Some problem occurred" });
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
app.get("/allusers", auth, async (req, res) => {
  try {
    const loggedInUserId = req.user._id; // assuming `auth` middleware attaches the user object
    const users = await User.find({ _id: { $ne: loggedInUserId } }); // exclude current user
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


// Socket setup

const server = http.createServer(app);
const io = socketIO(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

let onlineUsers = new Map();

io.on('connection', (socket) => {
  console.log('New socket connection:', socket.id);

  socket.on('join', (userId) => {
    onlineUsers.set(userId, socket.id);
    io.emit('onlineUsers', Array.from(onlineUsers.keys()));
  });

socket.on('sendMessage', async ({ senderId, receiverId, message }) => {
  try {
    const sender = await User.findById(senderId);
    const receiver = await User.findById(receiverId);

    const senderFollowsReceiver = sender.following.map(id => id.toString()).includes(receiverId.toString());
    const receiverFollowsSender = receiver.following.map(id => id.toString()).includes(senderId.toString());

    if (!senderFollowsReceiver || !receiverFollowsSender) {
      return; // Block the message from being saved or sent
    }

    const newMsg = await Message.create({ sender: senderId, receiver: receiverId, message });

    const receiverSocket = onlineUsers.get(receiverId);
    if (receiverSocket) {
      io.to(receiverSocket).emit('receiveMessage', newMsg);
    }

    io.to(socket.id).emit('receiveMessage', newMsg); // Optional: echo back to sender
  } catch (err) {
    console.error("Error in sendMessage:", err);
  }
});



  socket.on('disconnect', () => {
    for (let [userId, sockId] of onlineUsers.entries()) {
      if (sockId === socket.id) onlineUsers.delete(userId);
    }
    io.emit('onlineUsers', Array.from(onlineUsers.keys()));
    console.log('Socket disconnected:', socket.id);
  });
});

// chat endpoint 

app.get("/chat/:userId", auth, async (req, res) => {
  try {
    const userId = req.user.id;
    const targetId = req.params.userId;

    const user = await User.findById(userId);
    const targetUser = await User.findById(targetId);

    const userFollowsTarget = user.following.includes(targetId);
    const targetFollowsUser = targetUser.following.includes(userId);

    if (!userFollowsTarget || !targetFollowsUser) {
      return res.status(403).json({ error: "You must follow each other to chat." });
    }

    const messages = await Message.find({
      $or: [
        { sender: userId, receiver: targetId },
        { sender: targetId, receiver: userId }
      ]
    }).sort('createdAt');

    res.json(messages);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


app.listen(port, () => {
    console.log(`Server is up and running on port ${port}`);
});
