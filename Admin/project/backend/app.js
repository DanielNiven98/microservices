const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const multer = require("multer");
const axios = require("axios");
const path = require("path");
const { Storage } = require("@google-cloud/storage");
require("dotenv").config();

// ---------------- Configuration ---------------- //
const JWT_SECRET = process.env.JWT_SECRET || "your-very-secure-secret-key";
const MONGO_URI = process.env.MONGO_URI || "mongodb://mongo:27017/AdminDB"; // AdminDB connection
const GCS_BUCKET_NAME = process.env.GCS_BUCKET_NAME || "nivenmoviebucket"; // Updated bucket name
const PORT = process.env.PORT || 8080; // Admin side port

const app = express();

// ---------------- Google Cloud Storage Setup ---------------- //
const storage = new Storage({ projectId: process.env.GCP_PROJECT_ID });
const bucket = storage.bucket(GCS_BUCKET_NAME);

// ---------------- MongoDB Connection ---------------- //
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));


// ---------------- Mongoose Schema & Model ---------------- //
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  resetToken: String,
  resetTokenExpiry: Date,
  role: { type: String, default: 'user' }, // Added role field for admin
  watchlist: [{ type: String }], // Array to store the IDs or URLs of videos
});

const User = mongoose.model("User", userSchema);

// ---------------- Middleware ---------------- //
app.use(express.json());
app.use(
  cors({
    origin: [
      "http://localhost:8080",
      "https://bc6d355d6e1d.vfs.cloud9.us-east-1.amazonaws.com", // Cloud9 URL
    ],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);
app.use(express.static(path.join(__dirname, "../frontend"))); // Serve static files

// ---------------- Helper Functions ---------------- //
const generateToken = (payload) =>
  jwt.sign(payload, JWT_SECRET, { expiresIn: "1h", algorithm: "HS256" });

const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ message: "Unauthorized: Token missing or invalid format." });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] }, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token." });
    }

    req.user = decoded; // Attach the decoded user to the request object
    next();
  });
};

// ---------------- Routes ---------------- //

// Health Check Route
app.get("/health", (req, res) => res.status(200).send("API is running!"));

// Serve Static Files (Frontend Pages)
app.get("/", (req, res) => res.redirect("/login.html"));
app.get("/login.html", (req, res) =>
  res.sendFile(path.join(__dirname, "../frontend/login.html"))
);
app.get("/signup.html", (req, res) =>
  res.sendFile(path.join(__dirname, "../frontend/signup.html"))
);

// Create User Route (Writes to UserDB)
app.post("/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: "All fields are required." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();

    res.status(201).json({ message: "User created successfully in UserDB." });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({ message: "Username or email already exists." });
    }
    res.status(500).json({ message: "Error creating user in UserDB. Please try again." });
  }
});

// Edit User Route (Update user info in UserDB)
app.put("/users/:username", authenticateJWT, async (req, res) => {
  try {
    const { username } = req.params;
    const { newUsername, email } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    if (newUsername) user.username = newUsername;
    if (email) user.email = email;

    await user.save();
    res.status(200).json({ message: "User updated successfully." });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ message: "An error occurred while updating the user." });
  }
});

// Delete User from User Microservice
app.delete("/users/:username", authenticateJWT, async (req, res) => {
  try {
    const { username } = req.params;

    // API request to the User microservice
    const userMicroserviceUrl = `http://localhost:8082/users/${username}`;
    const response = await axios.delete(userMicroserviceUrl, {
      headers: {
        Authorization: req.headers.authorization, // Pass the JWT token
      },
    });

    if (response.status === 200) {
      res.status(200).json({ message: "User deleted successfully." });
    } else {
      res.status(response.status).json(response.data);
    }
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({ message: "An error occurred while deleting the user." });
  }
});

// Fetch All Users from UserDB
app.get("/users", authenticateJWT, async (req, res) => {
  try {
    const users = await User.find(); // Fetch all users from UserDB
    res.status(200).json({ source: "UserDB", users }); // Return the list of users and source
  } catch (error) {
    console.error("Error fetching users from UserDB:", error);
    res.status(500).json({ message: "Error fetching users from UserDB." });
  }
});

// Fetch Users from AdminDB
app.get("/admin/users", authenticateJWT, async (req, res) => {
  try {
    const users = await User.find(); // Fetch all users from AdminDB
    res.status(200).json({ source: "AdminDB", users }); // Return the list of users and source
  } catch (error) {
    console.error("Error fetching users from AdminDB:", error);
    res.status(500).json({ message: "Error fetching users from AdminDB." });
  }
});

// ---------------- Video Upload and Watchlist ---------------- //

// Video upload route
app.post(
  "/movies/upload",
  authenticateJWT,
  multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 1024 * 1024 * 1024 }, // Max size 1 GB
    fileFilter: (req, file, cb) => {
      if (!file.mimetype.startsWith("video/")) {
        return cb(new Error("Only video files are allowed!"), false);
      }
      cb(null, true);
    },
  }).single("video"),
  async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ message: "No file provided." });
    }

    const file = req.file;
    const sanitizedFileName = file.originalname.replace(/\s+/g, "_").toLowerCase();
    const gcsFile = bucket.file(`videos/${sanitizedFileName}`);

    try {
      const stream = gcsFile.createWriteStream({
        metadata: { contentType: file.mimetype },
        resumable: false,
      });

      stream.on("error", (err) => {
        return res.status(500).json({ message: "Error uploading video to GCS." });
      });

      stream.on("finish", async () => {
        const publicUrl = `https://storage.googleapis.com/${GCS_BUCKET_NAME}/videos/${sanitizedFileName}`;
        res.status(201).json({
          message: "Video uploaded successfully.",
          url: publicUrl,
        });
      });

      stream.end(file.buffer);
    } catch (error) {
      res.status(500).json({ message: "Error uploading video." });
    }
  }
);

// Fetch movies
app.get("/movies", authenticateJWT, async (req, res) => {
  try {
    const [files] = await bucket.getFiles({ prefix: "videos/" });
    const videos = files
      .filter((file) => file.name.endsWith(".mp4"))
      .map((file) => ({
        title: file.name.replace("videos/", ""),
        url: `https://storage.googleapis.com/${GCS_BUCKET_NAME}/${file.name}`,
      }));
    res.status(200).json(videos);
  } catch (error) {
    res.status(500).json({ message: "Error fetching videos from the bucket." });
  }
});

// Add User to the Watchlist
app.post("/watchlist/add", authenticateJWT, async (req, res) => {
  const { videoUrl } = req.body;

  if (!videoUrl) {
    return res.status(400).json({ message: "Video URL is required." });
  }

  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    if (!user.watchlist.includes(videoUrl)) {
      user.watchlist.push(videoUrl);
      await user.save();
    }

    res.status(200).json({ message: "Video added to watchlist successfully." });
  } catch (error) {
    res.status(500).json({ message: "Error adding video to watchlist." });
  }
});

// Remove video from the user's watchlist
app.post("/watchlist/remove", authenticateJWT, async (req, res) => {
  const { videoUrl } = req.body;

  if (!videoUrl) {
    return res.status(400).json({ message: "Video URL is required." });
  }

  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    user.watchlist = user.watchlist.filter((url) => url !== videoUrl);
    await user.save();

    res.status(200).json({ message: "Video removed from watchlist." });
  } catch (error) {
    res.status(500).json({ message: "Error removing video from watchlist." });
  }
});

// Fetch the user's watchlist
app.get("/watchlist", authenticateJWT, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    res.status(200).json({ watchlist: user.watchlist });
  } catch (error) {
    res.status(500).json({ message: "Error fetching watchlist." });
  }
});

// User Login
app.post("/login", async (req, res) => {
  try {
    const { emailOrUsername, password } = req.body;
    const user = await User.findOne({
      $or: [{ username: emailOrUsername }, { email: emailOrUsername }],
    });

    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: "Incorrect password." });
    }

    const token = generateToken({ email: user.email, username: user.username });
    res.json({ message: "Login successful.", token });
  } catch (error) {
    res.status(500).json({ message: "Error logging in. Please try again." });
  }
});


// ---------------- Start Server ---------------- //
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Admin microservice running on http://localhost:${PORT}`);
});