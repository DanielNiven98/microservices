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
    console.warn("Token missing or invalid format in the request header.");
    return res
      .status(401)
      .json({ message: "Unauthorized: Token missing or invalid format." });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] }, (err, decoded) => {
    if (err) {
      console.error("Token verification failed:", err);
      return res.status(403).json({ message: "Invalid or expired token." });
    }

    console.log("Token successfully verified for:", decoded.username || decoded.email);
    req.user = decoded; // Attach decoded user information to the request
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

// Fetch Users from UserDB
app.get("/users", authenticateJWT, async (req, res) => {
  try {
    const userDbConnection = mongoose.createConnection("mongodb://user-mongo:27017/UserDB", { useNewUrlParser: true, useUnifiedTopology: true });
    const UserModel = userDbConnection.model("User", userSchema); // Use the same User schema for querying UserDB
    const users = await UserModel.find(); // Fetch all users from UserDB

    res.status(200).json({ source: "UserDB", users }); // Return the list of users and source
  } catch (error) {
    console.error("Error fetching users from UserDB:", error);
    res.status(500).json({ message: "Error fetching users from UserDB." });
  }
});

// Create Regular User (Only writes to UserDB)
app.post("/createUser", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: "All fields are required." });
    }

    // Ensure we are writing to the UserDB
    const userDbConnection = mongoose.createConnection("mongodb://user-mongo:27017/UserDB", { useNewUrlParser: true, useUnifiedTopology: true });
    const UserModel = userDbConnection.model("User", userSchema); // Use the User schema for the UserDB

    // Hash the password before saving
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new UserModel({ username, email, password: hashedPassword });
    
    await user.save();
    res.status(201).json({ message: "User created successfully in UserDB." });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({ message: "Username or email already exists." });
    }
    res.status(500).json({ message: "Error creating user in UserDB. Please try again." });
  }
});

// Delete Regular User (Deletes from UserDB)
app.delete("/deleteUser/:username", async (req, res) => {
  try {
    const { username } = req.params;

    if (!username) {
      return res.status(400).json({ message: "Username is required." });
    }

    // Ensure we are connected to the UserDB
    const userDbConnection = mongoose.createConnection("mongodb://user-mongo:27017/UserDB", { useNewUrlParser: true, useUnifiedTopology: true });
    const UserModel = userDbConnection.model("User", userSchema);

    // Find and delete the user by username
    const deletedUser = await UserModel.findOneAndDelete({ username });
    if (!deletedUser) {
      return res.status(404).json({ message: "User not found in UserDB." });
    }

    res.status(200).json({ message: `User '${username}' deleted successfully from UserDB.` });
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({ message: "An error occurred while deleting the user from UserDB." });
  }
});

app.put("/editUser/:username", async (req, res) => {
  try {
    const { username } = req.params; // Existing username
    const { newUsername, email } = req.body; // New values

    // Connect to UserDB
    const userDbConnection = mongoose.createConnection("mongodb://user-mongo:27017/UserDB", {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    const UserModel = userDbConnection.model("User", userSchema);

    // Find user by current username and update
    const user = await UserModel.findOneAndUpdate(
      { username },
      { username: newUsername, email },
      { new: true } // Return the updated user
    );

    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    res.status(200).json({ message: "User updated successfully.", user });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ message: "An error occurred while updating the user." });
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

// User Signup
app.post("/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: "All fields are required." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();

    res.status(201).json({ message: "User registered successfully." });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({ message: "Username or email already exists." });
    }
    res.status(500).json({ message: "Error registering user. Please try again." });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { emailOrUsername, password } = req.body;
    console.log(`Login attempt for: ${emailOrUsername}`); // Log the login attempt

    const user = await User.findOne({
      $or: [{ username: emailOrUsername }, { email: emailOrUsername }],
    });

    if (!user) {
      console.log(`Login failed - User not found: ${emailOrUsername}`);
      return res.status(404).json({ message: "User not found." });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      console.log(`Login failed - Incorrect password for user: ${emailOrUsername}`);
      return res.status(401).json({ message: "Incorrect password." });
    }

    const token = generateToken({ email: user.email, username: user.username });
    console.log(`Token generated for user: ${emailOrUsername}, Token: ${token}`); // Log token generation

    // Return the token directly in the response
    res.status(200).json({ token });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ message: "Error logging in. Please try again." });
  }
});


// Fetch Logged-In User Info
app.get("/user", authenticateJWT, (req, res) => {
  res.json({
    email: req.user.email,
    username: req.user.username,
  });
});

// Update User Profile
app.put("/user/update", authenticateJWT, async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    if (!email && !newPassword) {
      return res.status(400).json({ message: "Please provide an email or new password." });
    }

    const user = await User.findOne({ username: req.user.username });
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    if (email) {
      user.email = email;
    }
    if (newPassword) {
      user.password = await bcrypt.hash(newPassword, 10);
    }

    await user.save();
    res.status(200).json({ message: "Profile updated successfully." });
  } catch (error) {
    console.error("Error during profile update:", error);
    res.status(500).json({ message: "An error occurred while updating your profile." });
  }
});

// Edit Admin User (AdminDB)
app.put("/editAdmin/:username", authenticateJWT, async (req, res) => {
  try {
    const { username } = req.params; // Current username
    const { newUsername, email } = req.body; // New data to update

    // Find the user in AdminDB and update
    const updatedAdmin = await User.findOneAndUpdate(
      { username },
      { username: newUsername, email },
      { new: true } // Return the updated user
    );

    if (!updatedAdmin) {
      return res.status(404).json({ message: "Admin user not found." });
    }

    res.status(200).json({ message: "Admin user updated successfully.", user: updatedAdmin });
  } catch (error) {
    console.error("Error updating admin user:", error);
    res.status(500).json({ message: "An error occurred while updating the admin user." });
  }
});


app.get('/health', (req, res) => {
  res.status(200).send('OK');
});


// ---------------- Start Server ---------------- //
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Admin microservice running on http://localhost:${PORT}`);
});