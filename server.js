require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();

// =============================
// 🔐 SECURITY MIDDLEWARE
// =============================
app.use(helmet());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

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
  role: { type: String, default: "user" },
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

  if (!header) return res.status(401).json({ message: "No token" });

  const token = header.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Invalid token format" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid or expired token" });
  }
}

// =============================
// VERIFY
// =============================
app.get("/verify", verifyToken, (req, res) => {
  res.json({ user: req.user });
});

// =============================
// REGISTER
// =============================
app.post("/register", async (req, res) => {
  try {
    const { name, username, password } = req.body;

    if (!name || !username || !password) {
      return res.status(400).json({ message: "All fields required ❌" });
    }

    // ✅ NEW: Basic password validation
    if (password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters ❌" });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "User exists ❌" });
    }

    const hashed = await bcrypt.hash(password, 10);

    await User.create({
      name,
      username,
      password: hashed,
      role: "user" // 🔥 FIXED: No auto admin
    });

    res.json({ message: "Registered ✅" });

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

    if (!username || !password) {
      return res.status(400).json({ message: "Missing credentials ❌" });
    }

    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ message: "Invalid ❌" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Invalid ❌" });

    const token = jwt.sign(
      {
        id: user._id,
        username: user.username,
        role: user.role,
        name: user.name
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      token,
      role: user.role,
      name: user.name
    });

  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

// =============================
// UPDATE SCORE
// =============================
app.post("/update-score", verifyToken, async (req, res) => {
  try {
    const { game, score } = req.body;

    const user = await User.findById(req.user.id);

    if (!user || !(game in user.scores)) {
      return res.status(400).json({ message: "Invalid game ❌" });
    }

    if (score > user.scores[game]) {
      user.scores[game] = score;
      await user.save();
    }

    res.json({ message: "Score updated ✅" });

  } catch {
    res.status(500).json({ message: "Error updating score" });
  }
});

// =============================
// LEADERBOARD
// =============================
app.get("/leaderboard/:game", async (req, res) => {
  try {
    const game = req.params.game;

    const users = await User.find(
      {},
      { username: 1, name: 1, [`scores.${game}`]: 1 }
    )
      .sort({ [`scores.${game}`]: -1 })
      .limit(10);

    res.json(users);

  } catch {
    res.status(500).json({ message: "Error leaderboard" });
  }
});

// =============================
// GET MY SCORE
// =============================
app.get("/my-score/:game", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const score = user?.scores?.[req.params.game] || 0;
    res.json({ score });
  } catch {
    res.status(500).json({ message: "Error fetching score" });
  }
});

// =============================
// 🔥 ADMIN ROUTES
// =============================
app.get("/admin/users", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ message: "Access denied ❌" });
    }

    const users = await User.find({}, {
      name: 1,
      username: 1,
      role: 1
    });

    res.json(users);

  } catch {
    res.status(500).json({ message: "Error fetching users" });
  }
});

app.delete("/admin/user/:id", verifyToken, async (req, res) => {
  try {
    if (req.user.role !== "admin") {
      return res.status(403).json({ message: "Access denied ❌" });
    }

    if (req.user.id === req.params.id) {
      return res.status(400).json({ message: "Cannot delete yourself ❌" });
    }

    await User.findByIdAndDelete(req.params.id);

    res.json({ message: "User deleted ✅" });

  } catch {
    res.status(500).json({ message: "Delete failed" });
  }
});

// =============================
// CHANGE PASSWORD
// =============================
app.post("/change-password", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    const match = await bcrypt.compare(req.body.oldPassword, user.password);
    if (!match) return res.status(400).json({ message: "Wrong password ❌" });

    user.password = await bcrypt.hash(req.body.newPassword, 10);
    await user.save();

    res.json({ message: "Updated 🔐" });

  } catch {
    res.status(500).json({ message: "Error updating password" });
  }
});

// =============================
app.get("/", (req, res) => {
  res.send("Server running 🚀");
});

// =============================
app.listen(process.env.PORT || 3000, () => {
  console.log("Server started 🚀");
});
