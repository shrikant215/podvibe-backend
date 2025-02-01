  import bcrypt from 'bcryptjs';
  import User from '../models/User.js';
  import jwt from "jsonwebtoken";
  import nodemailer from "nodemailer";
  import dotenv from 'dotenv';
import randomstring from 'randomstring';

  dotenv.config();

  
  export const login = async (req, res) => {
    const { email, password } = req.body;
  
    try {
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(401).json({ message: 'Invalid email or password' });
      }
  
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).json({ message: 'Invalid email or password' });
      }
  
      const token = jwt.sign(
        { id: user._id }, 
        process.env.JWT_SECRET, 
        { expiresIn: '7d' } 
      );
  
      res.status(200).json({
        message: 'Login Successful',
        token,
        user: {
          id: user._id,
          email: user.email,
          name: user.name, 
        },
      });
    } catch (error) {
      console.error('Error during login:', error);
      res.status(500).json({ message: 'Server error. Please try again later.' });
    }
  };
  

  export const signup = async (req, res) => {
    const { name, email, password, otp } = req.body;

    if (!otpMap[email] || otpMap[email] !== otp) {
      return res.status(400).json({ message: 'Invalid OTP.' });
    }

    try {
      const existingUser = await User.findOne({ email });
      if (existingUser) return res.status(400).json({ message: 'Email already registered.' });

      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new User({ name, email, password: hashedPassword });
      await newUser.save().then((user) => {
        const  token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '9999 years'});
        res.status(200).json({ message: 'Signup Successful', token,
           user: {
               id: newUser._id,
               email: newUser.email,
               name: newUser.name,
        } });
      }).catch((err) => {
        console.log(err);
      })

    } catch (error) {
      res.status(500).json({ message: error });
    }
  };

  export const logout = (req, res) => {
    res.clearCookie("access_token").json({ message: "Logged out" });
    };


  // Simulated in-memory database for storing OTPs  
  const otpMap = {};
  
  export const sendSignupOTP = async (req, res) => {
    const { email } = req.body;
    console.log('Email:', email);
  
    if (!email) {
      return res.status(400).json({ message: 'Email is required.' });
    }
  
    try {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: 'Email already registered.' });
      }
  
      const otp = randomstring.generate({ length: 6, charset: 'numeric' });
      otpMap[email] = otp;
  
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS,
        },
      });
  
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'OTP for Signup',
        text: `Your OTP for signup is: ${otp}`,
      };
  
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Email error:', error);
          return res.status(500).json({ message: 'Failed to send OTP.', error });
        }
        console.log('Email sent successfully:', info.response);
        res.status(200).json({ message: 'OTP sent successfully.' });
      });
    } catch (error) {
      console.error('Error:', error);
      res.status(500).json({ message: 'Internal server error', error });
    }
  };
  

  // Route to verify OTP for signup
  export const verifySignupOTP = (req, res) => {
    const { email, otp } = req.body;
// console.log(email, otp)
    try {
      // Verify OTP
      if (!otpMap[email] || otpMap[email] !== otp) {
        return res.status(400).json({ message: 'Invalid OTP.' });
      }

      // Optionally delete OTP after verification
      delete otpMap[email];

      res.status(200).json({ message: 'OTP verification successful.' });
    } catch (error) {
      console.error('Error in verifying OTP:', error.message);
      res.status(500).json({ message: 'Internal server error' });
    }
  };