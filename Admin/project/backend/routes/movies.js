const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const router = express.Router();

// Directory to store videos
const VIDEO_DIR = path.join(__dirname, '../videos');

// Ensure the video directory exists
if (!fs.existsSync(VIDEO_DIR)) {
  fs.mkdirSync(VIDEO_DIR, { recursive: true });
}

// Configure Multer for video uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, VIDEO_DIR);
  },
  filename: (req, file, cb) => {
    const sanitizedFileName = file.originalname.replace(/\s+/g, '_').toLowerCase();
    cb(null, sanitizedFileName);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 1024 * 1024 * 1024 }, // 1 GB limit
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('video/')) {
      return cb(new Error('Only video files are allowed!'), false);
    }
    cb(null, true);
  },
});


// Fetch the list of videos
router.get('/', (req, res) => {
  fs.readdir(VIDEO_DIR, (err, files) => {
    if (err) {
      console.error('Error reading video directory:', err);
      return res.status(500).json({ message: 'Error fetching videos.' });
    }

    const movies = files
      .filter(file => file.endsWith('.mp4'))
      .map(file => ({
        title: file.replace('.mp4', ''),
        streamUrl: `/videos/${file}`, // FIXED: Proper string interpolation
      }));

    if (movies.length === 0) {
      return res.status(404).json({ message: 'No videos found.' });
    }

    res.json(movies);
  });
});

module.exports = router;