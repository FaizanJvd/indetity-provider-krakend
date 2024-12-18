const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const connectDB = require("./config/db");
connectDB();
const User = require('./models/User');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 4000;

app.use(bodyParser.json());

// Route: POST /signup - Register a new user
app.post('/signup', async (req, res) => {
    const { userName, email, password, phoneNo } = req.body;
  
    // Input validation
    if (!userName || !email || !password || !phoneNo) {
      return res.status(400).json({ error: 'All fields are required' });
    }
  
    try {
      // Check if user already exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ error: 'User already exists' });
      }
  
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Create new user
      const user = new User({
        userName,
        email,
        password: hashedPassword,
        phoneNo,
      });
  
      await user.save();
  
      return res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
      console.error('Error registering user:', error.message);
      return res.status(500).json({ error: 'Server error' });
    }
  });

// Endpoint to authenticate user and issue a JWT token
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    // Find user by email
        const user = await User.findOne({ email });
        if (!user) {
        return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Compare passwords
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
        return res.status(400).json({ error: 'Invalid credentials' });
        }
        var signOptions = {
            header: { kid:"sim2"},
            expiresIn:  "1h"
        };

        const access_token = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET, signOptions);

        const refreshToken = jwt.sign({ userId: user._id, email: user.email }, process.env.JWT_SECRET,{header: { kid: "sim2" }, expiresIn:"1d"})

        const response = {
            "user":user,
            "access_token": access_token,
            "refresh_token": refreshToken,
        }
        return res.status(200).json(response);
    } catch (error) {
        console.error('Error logging in:', error.message);
        return res.status(500).json({ error: 'Server error' });
    }
});

// Example of an API endpoint that requires authentication
app.get('/jwk', (req, res) => {
    res.json({
      keys: [
        {
          "alg": "HS256",
          "kty": "oct",
          "kid": "sim2",
          "k": "c2VjcmV0"
        }
      ]
    });
  });
  

app.listen(PORT, () => {
    console.log(`Server running at ${PORT}`);
});
