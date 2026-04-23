require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();

// =============================
// MIDDLEWARE
// =============================
app.use(express.json());
app.use(cors());

// =============================
// CONNECT DB
// =============================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected ✅"))
  .catch(err => console.log(err));

// =============================
// USER SCHEMA
// =============================
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  username: { type: String, unique: true },
  password: String,
  role: {
    type: String,
    default: "user"
  },

  scores: {
    game1: { type: Number, default: 0 },
    game2: { type: Number, default: 0 }
  }
});

const User = mongoose.model("User", userSchema);

// =============================
// AUTH MIDDLEWARE
// =============================
function verifyToken(req, res, next) {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({ message: "No token" });
  }

  const token = header.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Invalid token format" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }
    req.user = decoded;
    next();
  });
}

function verifyAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin only" });
  }
  next();
}

// =============================
// VERIFY
// =============================
app.get("/verify", verifyToken, (req, res) => {
  res.json({
    message: "Token valid ✅",
    user: req.user
  });
});

// =============================
// REGISTER
// =============================
app.post("/register", async (req, res) => {
  try {
    const { name, username, password } = req.body;

    if (!name || !username || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists ❌" });
    }

    const hashed = await bcrypt.hash(password, 10);

    await User.create({
      name,
      username,
      password: hashed
    });

    res.json({ message: "Registered successfully ✅" });

  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// =============================
// LOGIN
// =============================
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials ❌" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ message: "Invalid credentials ❌" });
    }

    const token = jwt.sign(
      {
        id: user._id,
        username: user.username,
        role: user.role,
        name: user.name
      },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    );

    res.json({
      token,
      role: user.role,
      name: user.name,
      username: user.username
    });

  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// =============================
// 🔥 UPDATE SCORE (FIXED)
// =============================
app.post("/update-score", verifyToken, async (req, res) => {
  try {
    const { game, score } = req.body;

    if (!game || score === undefined) {
      return res.status(400).json({ message: "Game and score required" });
    }

    const user = await User.findById(req.user.id);

    // ✅ FIXED: correct validation
    if (!(game in user.scores)) {
      return res.status(400).json({ message: "Invalid game ❌" });
    }

    // ✅ update only if higher
    if (score > user.scores[game]) {
      user.scores[game] = score;
      await user.save();
    }

    res.json({ message: "Score updated ✅" });

  } catch (err) {
    res.status(500).json({ message: "Error updating score" });
  }
});

// =============================
// 🏆 LEADERBOARD
// =============================
app.get("/leaderboard/:game", async (req, res) => {
  try {
    const game = req.params.game;

    if (!["game1", "game2"].includes(game)) {
      return res.status(400).json({ message: "Invalid game ❌" });
    }

    const users = await User.find(
      {},
      { username: 1, name: 1, [`scores.${game}`]: 1 }
    )
      .sort({ [`scores.${game}`]: -1 })
      .limit(10);

    res.json(users);

  } catch (err) {
    res.status(500).json({ message: "Error fetching leaderboard" });
  }
});

// =============================
// CHANGE PASSWORD
// =============================
app.post("/change-password", verifyToken, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    const user = await User.findById(req.user.id);

    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Old password incorrect ❌" });
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    user.password = hashed;

    await user.save();

    res.json({ message: "Password updated 🔐" });

  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// =============================
// ROOT
// =============================
app.get("/", (req, res) => {
  res.send("Server running with leaderboard 🚀");
});

// =============================
// START SERVER
// =============================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server started on port ${PORT} 🚀`);
});
