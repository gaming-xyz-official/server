require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();

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
  username: { type: String, unique: true },
  password: String,
  role: {
    type: String,
    default: "user" // or "admin"
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

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
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
// REGISTER
// =============================
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  const hashed = await bcrypt.hash(password, 10);

  try {
    await User.create({ username, password: hashed });
    res.json({ message: "Registered" });
  } catch {
    res.status(400).json({ message: "User exists" });
  }
});

// =============================
// LOGIN
// =============================
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });
  if (!user) return res.status(401).json({ message: "Invalid" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ message: "Invalid" });

  const token = jwt.sign(
    {
      id: user._id,
      username: user.username,
      role: user.role
    },
    process.env.JWT_SECRET,
    { expiresIn: "2h" }
  );

  res.json({ token, role: user.role });
});

// =============================
// ADMIN ROUTES
// =============================

// GET ALL USERS
app.get("/admin/users", verifyToken, verifyAdmin, async (req, res) => {
  const users = await User.find().select("-password");
  res.json(users);
});

// DELETE USER
app.delete("/admin/user/:id", verifyToken, verifyAdmin, async (req, res) => {
  if (req.params.id === req.user.id) {
    return res.json({ message: "You can't delete yourself" });
  }

  await User.findByIdAndDelete(req.params.id);
  res.json({ message: "Deleted" });
});

// =============================
app.get("/", (req, res) => {
  res.send("Server running ✅");
});

// =============================
app.listen(3000, () => console.log("Server started 🚀"));
