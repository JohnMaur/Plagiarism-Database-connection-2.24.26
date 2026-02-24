require('dotenv').config();
const express = require('express');
const { MongoClient, ServerApiVersion } = require('mongodb');
const bodyParser = require('body-parser');
const cors = require("cors");
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors({ origin: "*" }));
app.use(bodyParser.json()); // Parse JSON request bodies

// MongoDB URI and client setup
const uri = "mongodb+srv://bdictuz14:6rxKFDaZ1PsmAOEC@cluster0.qjugz.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// Connect to MongoDB
let db;
client.connect().then(() => {
  console.log('Connected to MongoDB Atlas!');
  db = client.db('account_db'); // Select database
});

// Secret for JWT
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";

// Helper function to generate JWT
const generateToken = (user) => {
  return jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '7d' }); // Token valid for 7 days
};

// Middleware to authenticate JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access token required.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token.' });
    req.user = user;
    next();
  });
};

// API to create a user account
app.post('/api/signup', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required.' });
    }

    // Check if the user already exists
    const existingUser = await db.collection('users').findOne({ username });
    if (existingUser) {
      return res.status(409).json({ message: 'Account already exists.' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user
    await db.collection('users').insertOne({ username, password: hashedPassword });
    return res.status(201).json({ message: 'Account created successfully.' });
  } catch (err) {
    console.error('Error creating account:', err);
    return res.status(500).json({ message: 'Internal server error.' });
  }
});

// API to log in
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required.' });
    }

    // Find user by username
    const user = await db.collection('users').findOne({ username });
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    // Compare password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // Generate token
    const token = generateToken(user);

    // Login successful, send token
    return res.status(200).json({ message: 'Login successful', token });
  } catch (err) {
    console.error('Error during login:', err);
    return res.status(500).json({ message: 'Internal server error.' });
  }
});

// Example protected route
app.get('/api/protected', authenticateToken, (req, res) => {
  res.status(200).json({ message: 'Access granted.', user: req.user });
});

// API to change password
app.post('/api/change-password', authenticateToken, async (req, res) => {
  try {
    const { newPassword } = req.body;
    const username = req.user.username;

    if (!newPassword || newPassword.length < 8) {
      return res.status(400).json({ message: "Invalid password." });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.collection('users').updateOne(
      { username },
      { $set: { password: hashedPassword } }
    );

    return res.status(200).json({ message: "Password changed successfully." });
  } catch (err) {
    console.error('Error changing password:', err);
    return res.status(500).json({ message: "Internal server error." });
  }
});

// API to update user profile (requires authentication)
app.put('/api/update-profile', authenticateToken, async (req, res) => {
  try {
    const { email, fullName, address } = req.body;
    const username = req.user.username; // Extract username from JWT

    if (!email && !fullName && !address) {
      return res.status(400).json({ message: "No update data provided." });
    }

    // Update user details
    const updateFields = {};
    if (email) updateFields.email = email;
    if (fullName) updateFields.fullName = fullName;
    if (address) updateFields.address = address;

    const result = await db.collection('users').updateOne(
      { username },
      { $set: updateFields }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ message: "User not found or no changes made." });
    }

    return res.status(200).json({ message: "Profile updated successfully." });
  } catch (err) {
    console.error('Error updating profile:', err);
    return res.status(500).json({ message: "Internal server error." });
  }
});

app.get('/api/user-profile', authenticateToken, async (req, res) => {
  try {
    const user = await db.collection('users').findOne(
      { username: req.user.username },
      { projection: { email: 1, fullName: 1, address: 1, _id: 0 } } // Only return these fields
    );

    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    res.status(200).json(user);
  } catch (err) {
    console.error('Error fetching user profile:', err);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));