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

  // ✅ IMPORTANT: Extract token after "Bearer "
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
// 🔥 VERIFY ROUTE (MOST IMPORTANT FIX)
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
// CHANGE PASSWORD
// =============================
app.post("/change-password", verifyToken, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
      return res.status(400).json({ message: "All fields required" });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Old password incorrect ❌" });
    }

    const hashed = await bcrypt.hash(newPassword, 10);
    user.password = hashed;

    await user.save();

    res.json({ message: "Password updated. Please login again 🔐" });

  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// =============================
// ADMIN ROUTES
// =============================

// GET USERS
app.get("/admin/users", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const users = await User.find().select("-password");
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: "Error fetching users" });
  }
});

// DELETE USER
app.delete("/admin/user/:id", verifyToken, verifyAdmin, async (req, res) => {
  try {
    if (req.params.id === req.user.id) {
      return res.json({ message: "You can't delete yourself ❌" });
    }

    await User.findByIdAndDelete(req.params.id);
    res.json({ message: "User deleted ✅" });

  } catch (err) {
    res.status(500).json({ message: "Error deleting user" });
  }
});

// =============================
// ROOT
// =============================
app.get("/", (req, res) => {
  res.send("Server running ✅");
});

// =============================
// START SERVER
// =============================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server started on port ${PORT} 🚀`);
});
