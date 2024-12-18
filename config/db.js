const mongoose = require('mongoose');

const connectDB = async () => {
 
    const DATABASE_NAME = process.env.MONOGO_DATABASE_NAME || "krakend-test-db";
    const url = process.env.MONGO_URL || "mongodb://root:secret@localhost:43361"
  try {
    const MONGO_URI = process.env.MONGO_URI || `${url}/${DATABASE_NAME}?authSource=admin`;

    await mongoose.connect(MONGO_URI);
    console.log('✅ MongoDB connected successfully');

    // Graceful shutdown on SIGINT or process termination
    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      console.log('🛑 MongoDB connection closed due to app termination');
      process.exit(0);
    });
  } catch (error) {
    console.error('❌ MongoDB connection failed:', error.message);
    process.exit(1); // Exit with failure
  }
};

module.exports = connectDB;

