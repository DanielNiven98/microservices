const express = require('express');
const multer = require('multer');
const { Storage } = require('@google-cloud/storage');
const path = require('path');
const router = express.Router();

// Google Cloud Storage setup
const storage = new Storage();
const bucket = storage.bucket('nivenmoviebucket');  // Your GCS bucket name

// Multer configuration: Use memory storage for file uploads
const upload = multer({
  storage: multer.memoryStorage(), // Store file in memory
  limits: { fileSize: 1024 * 1024 * 1024 }, // 1 GB limit
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('video/')) {
      return cb(new Error('Only video files are allowed!'), false);
    }
    cb(null, true);
  },
});

router.post('/upload', upload.single('video'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No file provided.' });
  }

  const file = req.file;
  const sanitizedFileName = file.originalname.replace(/\s+/g, '_').toLowerCase();
  const gcsFile = bucket.file(`videos/${sanitizedFileName}`);

  try {
    const stream = gcsFile.createWriteStream({
      metadata: { 
        contentType: 'video/mp4' // Force the MIME type to video/mp4
      },
      resumable: false, // For simplicity
    });

    stream.on('error', (err) => {
      console.error('Error uploading to GCS:', err);
      return res.status(500).json({ message: 'Error uploading video to GCS.' });
    });

    stream.on('finish', async () => {
      // Make the file public after upload
      await gcsFile.makePublic();
      const publicUrl = `https://storage.googleapis.com/${GCS_BUCKET_NAME}/videos/${sanitizedFileName}`;

      res.status(201).json({
        message: 'Video uploaded successfully.',
        url: publicUrl,
      });
    });

    stream.end(file.buffer);
  } catch (error) {
    console.error('Error uploading video:', error);
    res.status(500).json({ message: 'Error uploading video.' });
  }
});


// Fetch the list of videos from GCS
router.get('/', async (req, res) => {
  try {
    const [files] = await bucket.getFiles({ prefix: 'videos/' });

    const movies = files.map((file) => ({
      title: file.name.replace('videos/', ''),  // Remove "videos/" prefix for cleaner display
      url: `https://storage.googleapis.com/nivenmoviebucket/${file.name}`, // Public GCS URL
    }));

    if (movies.length === 0) {
      return res.status(404).json({ message: 'No videos found.' });
    }

    res.json(movies);
  } catch (error) {
    console.error('Error fetching videos from GCS:', error);
    res.status(500).json({ message: 'Error fetching videos from GCS.' });
  }
});

module.exports = router;