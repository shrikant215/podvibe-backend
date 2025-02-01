import express from 'express';
import dotenv from 'dotenv';
import connectDB from './config/db.js';
import configurePassport from './config/passport.js';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import cors from 'cors';
import authRoutes from './routes/authRoutes.js';
import passport from 'passport';
import nodemailer from 'nodemailer';
import randomstring from 'randomstring';
import mongoose from 'mongoose';
// import dotenv from 'dotenv';

dotenv.config();



const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({ origin: 'https://podvibe-srjk-91bde6.netlify.app/', credentials: true }));
app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
  })
);

// Passport setup
configurePassport();
app.use(passport.initialize());
app.use(passport.session());

// Routes
app.use('/auth', authRoutes);

// Error handler middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  res.status(500).json({ message: 'Internal server error' });
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
  process.exit(1); // Exit to prevent further issues
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});


// Start the server
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
connectDB(process.env.MONGODB_URI);
