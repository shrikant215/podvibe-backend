import mongoose from 'mongoose';

const userSchema = new mongoose.Schema(
  {
    googleId: String,
    name: String,
    email: String,
    password: String,
    image: String,
  },
  { timestamps: true }
);

export default mongoose.model('User', userSchema);
