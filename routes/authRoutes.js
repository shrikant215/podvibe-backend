import express from 'express';
import passport from 'passport';
import { login, logout, signup, sendSignupOTP, verifySignupOTP } from '../controllers/authController.js';

const router = express.Router();

router.post('/login', login);
router.get('/logout', logout);
router.post('/signup', signup);

router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get(
  '/google/callback',
  passport.authenticate('google', { successRedirect: 'http://localhost:3000', failureRedirect: '/' })
);

router.post('/sendSignupOTP', sendSignupOTP);
router.post('/verifySignupOTP', verifySignupOTP);

export default router;
