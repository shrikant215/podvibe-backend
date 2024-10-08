// Import necessary modules
import dotenv from 'dotenv';
import express from 'express';
import mongoose from 'mongoose';
import bodyParser from 'body-parser';
import cors from 'cors';
import nodemailer from 'nodemailer';
import randomstring from 'randomstring';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { refreshToken } from 'firebase-admin/app';
import { profile } from 'console';
import session from "express-session";
import passport from "passport"
import { Strategy as OAuth2Strategy } from 'passport-google-oauth2';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import MongoStore from 'connect-mongo';


const userSchema = new mongoose.Schema(
  {
    googleId: String,
    displayName: String,
    email: String,
    password: String,
    image: String
  },
  { timestamps: true }
);
const User = mongoose.model("User", userSchema);

dotenv.config();

const app = express();
const uri = process.env.MONGODB_URI;

const clientId = process.env.GOOGLE_CLIENT_ID;
const clientsecret = process.env.GOOGLE_CLIENT_SECRET;



app.use(cors({
  origin: 'https://podvibe-srjk-91bde6.netlify.app',
  credentials: true,
}));

app.use(express.json());
app.use(bodyParser.json());
app.use("/uploads", express.static("uploads"));

// Function to generate a token
const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
};

//setup session
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  store: MongoStore.create({ mongoUrl: uri }), 
  cookie: { secure: false } 

}));

//setup
app.use(passport.initialize())
app.use(passport.session())

passport.use(
  new OAuth2Strategy({
    clientID: clientId,
    clientSecret: clientsecret,
    callbackURL: "https://podvibe-backend-server.onrender.com/auth/google/callback",
    scope: ["profile","email"],
  },
async(accessToken, refreshToken, profile,done)=>{
  console.log("profile", profile)
  try{
    if (!profile) {
      throw new Error('Profile object is null');
  }
  // console.log('Profile:', profile);
    let user = await User.findOne({googleId: profile.id});
    if(!user){
      user = new User({
        googleId: profile.id,
        displayName: profile.displayName,
        email: profile.emails[0].value,
        image: profile.photos[0].value
      });
      await user.save();
    }
    return done(null, user);
  }catch (error) {
    return done(error, null)
  }
})
);

passport.serializeUser(function(user, done) {
  done(null, user._id); // Store only the user ID in the session
});

passport.deserializeUser(async function(id, done) {
  try {
    const user = await User.findById(id);
    done(null, user); // Attach the full user object to req.user
  } catch (err) {
    done(err);
  }
});

// Initial Google OAuth login
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));


app.get('/auth/google/callback',
  passport.authenticate('google', { successRedirect:  'https://podvibe-srjk-91bde6.netlify.app', 
    failureRedirect: 'https://podvibe-srjk-91bde6.netlify.app' })
);

app.get("/sigin/sucess", async(req, res) => {
  console.log("dddddddddddddddd",req.user)
  // console.log("Session Data:", req.session);

  if (req.user) {
    console.log(req.user,"req.user")
    res.status(200).json({ message: "Login successful", user: req.user });
  } else {
    console.log("Not authorized")
    res.status(400).json({ message: "Not authorized" });
  }
})

app.get("/logout", (req, res) => {
  req.logOut(function(err){
    if(err){return next(err)}
    res.redirect( 'https://podvibe-srjk-91bde6.netlify.app');
  })
})



// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).send('Internal Server Error');
});

// Connect to MongoDB
mongoose
  .connect(uri, {
    // useNewUrlParser: true,
    // useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Error connecting to MongoDB:", err));

// Login endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    console.log("user",user)
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });
    console.log("!user",!user)

    // const isMatch = await bcrypt.compare(password, user.password);
    const isMatch = await bcrypt.compare(password, user.password);
    console.log("isMatch",isMatch)

    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

    const token = generateToken(user);

    res.status(200).json({ message: 'Login Successful', token, user });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Nodemailer transporter configuration
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Simulated in-memory database for storing OTPs
const otpMap = {};

// Route to send OTP for signup
app.post("/api/sendSignupOTP", async (req, res) => {
  const { email } = req.body;

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ message: "Email already registered." });
  }

  // Generate OTP
  const otp = randomstring.generate({
    length: 6,
    charset: "numeric",
  });

  // Save OTP to the in-memory database
  otpMap[email] = otp;

  // Email message configuration
  const mailOptions = {
    from: "shrikantjk3@gmail.com",
    to: email,
    subject: "OTP for Signup",
    text: `Your OTP for signup is: ${otp}`,
  };

  // Send email
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log(error);
      res.status(500).json({ message: "Failed to send OTP.", error });
    } else {
      console.log("Email sent: " + info.response);
      res.status(200).json({ message: "OTP sent successfully." });
    }
  });
});

// Route to verify OTP for signup
app.post("/api/verifySignupOTP", async (req, res) => {
  const { email, otp } = req.body;

  // Verify OTP
  if (!otpMap[email] || otpMap[email] !== otp) {
    return res.status(400).json({ message: "Invalid OTP." });
  }

  res.status(200).json({ message: "OTP verification successful." });
});

// Sign-up endpoint
app.post("/api/signup", async (req, res) => {
  const { displayName, email, password, otp } = req.body;

  // Verify OTP
  if (!otpMap[email] || otpMap[email] !== otp) {
    return res.status(400).json({ message: "Invalid OTP." });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Username already exists" });
    } else {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
console.log("hashedPassword",hashedPassword)
      const newUser = new User({ displayName, email, password: hashedPassword });
      await newUser.save();

      const token = generateToken(newUser);
      res.status(201).json({ message: "Sign-up successful", token, newUser });
      console.log("newUser", newUser);
    }
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


// Define port
const PORT = process.env.PORT || 5000;

// Start the server
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));

export default app;
