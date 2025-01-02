const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
require('dotenv').config();

// ---------------- Configuration ---------------- //
const JWT_SECRET = process.env.JWT_SECRET || 'your-very-secure-secret-key';
const MONGO_URI = process.env.MONGO_URI || 'mongodb://mongo:27017/AdminDB';
const VIDEO_DIR = path.join(__dirname, '../videos');
const PORT = process.env.PORT || 8080;

const app = express();

// ---------------- MongoDB Connection ---------------- //
mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// ---------------- Mongoose Schema & Model ---------------- //
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  resetToken: String,
  resetTokenExpiry: Date,
});

const User = mongoose.model('User', userSchema);

// ---------------- Middleware ---------------- //
app.use(express.json());
app.use(
  cors({
    origin: ['http://localhost:8080', 'https://bc6d355d6e1d.vfs.cloud9.us-east-1.amazonaws.com'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true,
  })
);
app.use(express.static(path.join(__dirname, '../frontend')));

// ---------------- Multer Configuration ---------------- //
if (!fs.existsSync(VIDEO_DIR)) {
  fs.mkdirSync(VIDEO_DIR, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, VIDEO_DIR),
  filename: (req, file, cb) => {
    const sanitizedFileName = file.originalname.replace(/\s+/g, '_').toLowerCase();
    cb(null, sanitizedFileName);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 1024 * 1024 * 1024 }, // 1GB Limit
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('video/')) {
      return cb(new Error('Only video files are allowed!'), false);
    }
    cb(null, true);
  },
});

// ---------------- Helper Functions ---------------- //
const generateToken = (payload) => jwt.sign(payload, JWT_SECRET, { expiresIn: '1h', algorithm: 'HS256' });

const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Unauthorized: Token missing or invalid format.' });
  }

  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token.' });
    }
    req.user = decoded;
    next();
  });
};

// ---------------- Routes ---------------- //

// Health Check Route
app.get('/health', (req, res) => res.status(200).send('API is running!'));

// Serve Login or Signup Page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/signup.html'));
});

// Fetch All Movies
app.get('/movies', authenticateJWT, (req, res) => {
  fs.readdir(VIDEO_DIR, (err, files) => {
    if (err) {
      console.error('Error reading video directory:', err);
      return res.status(500).json({ message: 'Error fetching videos.' });
    }

    const videos = files
      .filter((file) => file.endsWith('.mp4'))
      .map((file) => ({
        title: file.replace('.mp4', ''),
        streamUrl: `/videos/${file}`, // Fixed Proper Path
      }));

    res.json(videos.length ? videos : { message: 'No videos found.' });
  });
});

// Serve Video Files
app.use('/videos', express.static(VIDEO_DIR));

// Upload a New Movie
app.post('/movies/upload', authenticateJWT, (req, res) => {
  upload.single('video')(req, res, (err) => {
    if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ message: 'File is too large. Maximum allowed size is 1GB.' });
    } else if (err) {
      console.error('Error uploading video:', err);
      return res.status(500).json({ message: 'An error occurred while uploading the video.' });
    }

    if (!req.file) {
      return res.status(400).json({ message: 'No file provided.' });
    }

    res.status(201).json({
      message: 'Video uploaded successfully.',
      url: `/videos/${req.file.filename}`,
    });
  });
});

// User Signup
app.post('/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();

    res.status(201).json({ message: 'User registered successfully.' });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({ message: 'Username or email already exists.' });
    }
    res.status(500).json({ message: 'Error registering user. Please try again.' });
  }
});

// User Login
app.post('/login', async (req, res) => {
  try {
    const { emailOrUsername, password } = req.body;
    const user = await User.findOne({
      $or: [{ username: emailOrUsername }, { email: emailOrUsername }],
    });

    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Incorrect password.' });
    }

    const token = generateToken({ email: user.email, username: user.username });
    res.json({ message: 'Login successful.', token });
  } catch (error) {
    res.status(500).json({ message: 'Error logging in. Please try again.' });
  }
});

// Fetch Logged-In User Info
app.get('/user', authenticateJWT, (req, res) => {
  res.json({
    email: req.user.email,
    username: req.user.username,
  });
});

// Fetch All Users
app.get('/users', authenticateJWT, async (req, res) => {
  try {
    const users = await User.find({}, { password: 0 }); // Exclude password field
    res.status(200).json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Error fetching users. Please try again.' });
  }
});

// Edit User
app.put('/users/:username', authenticateJWT, async (req, res) => {
  const { username } = req.params;
  const { newUsername, email } = req.body;

  try {
    const user = await User.findOneAndUpdate(
      { username },
      { username: newUsername, email },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    res.status(200).json({ message: 'User updated successfully.', user });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ message: 'Error updating user. Please try again.' });
  }
});

// Delete User
app.delete('/users/:username', authenticateJWT, async (req, res) => {
  const { username } = req.params;

  try {
    const user = await User.findOneAndDelete({ username });

    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    res.status(200).json({ message: `User ${username} deleted successfully.` });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ message: 'Error deleting user. Please try again.' });
  }
});

// ---------------- Start Server ---------------- //
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
