import express from 'express';
import dotenv from 'dotenv';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import cors from 'cors';
import authRoutes from './routes/authRoutes.js';
import mongoose from 'mongoose';

dotenv.config();



const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({ origin: 'https://podvibe-srjk-91bde6.netlify.app', credentials: true }));
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
// app.use(passport.initialize());
// app.use(passport.session());

// Routes
app.use('/auth', authRoutes);



const connect = () => {
  mongoose.set('strictQuery', true);
  mongoose.connect(process.env.MONGODB_URI).then(() => {
      console.log('MongoDB connected');
  }).catch((err) => {
      console.log(err);
  });
};

app.use(express.json())

// Error handler middleware
app.use((err, req, res, next) => {
  const status = err.status || 500;
  const message = err.message || "Something went wrong";
  return res.status(status).json({
      success: false,
      status,
      message
  })
})


app.listen(PORT, () => {
  console.log("Connected")
  connect();
})
