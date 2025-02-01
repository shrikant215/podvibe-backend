import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

const connectDB = async () => {

  try {
    mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    })
    .then(() => console.log('✅ MongoDB Connected'))
    .catch((err) => {
      console.error('❌ MongoDB Connection Error:', err);
      process.exit(1);  // Exit the process if DB connection fails
    });
  } catch (err) {
    console.error('❌ Unexpected Error:', err);
    process.exit(1);  // Exit the process on unexpected errors
  }
  
};

export default connectDB;
