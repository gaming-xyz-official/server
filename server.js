const express = require("express");
const bcrypt = require("bcrypt");
const cors = require("cors");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();

// =============================
// MIDDLEWARE
// =============================
app.use(express.json());
app.use(cors({ origin: "*" }));

// =============================
// CONNECT TO MONGODB
// =============================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected ✅"))
  .catch(err => console.error("MongoDB Error:", err));

// =============================
// USER SCHEMA
// =============================
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String
});

const User = mongoose.model("User", userSchema);

// =============================
// ORDER SCHEMA
// =============================
const orderSchema = new mongoose.Schema({
  userId: String,
  items: [
    {
      name: String,
      price: Number,
      quantity: Number
    }
  ],
  totalAmount: Number,
  status: {
    type: String,
    default: "Pending"
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Order = mongoose.model("Order", orderSchema);

// =============================
// JWT VERIFY MIDDLEWARE
// =============================
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader)
    return res.status(401).json({ message: "Access denied. No token." });

  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err)
      return res.status(403).json({ message: "Invalid token" });

    req.user = decoded;
    next();
  });
}

// =============================
// REGISTER
// =============================
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password)
      return res.status(400).json({ message: "Username and password required" });

    const existingUser = await User.findOne({ username });
    if (existingUser)
      return res.status(409).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      password: hashedPassword
    });

    await newUser.save();

    res.json({ message: "User registered successfully" });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// =============================
// LOGIN
// =============================
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password)
      return res.status(400).json({ message: "Username and password required" });

    const user = await User.findOne({ username });
    if (!user)
      return res.status(401).json({ message: "Invalid username or password" });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(401).json({ message: "Invalid username or password" });

    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    );

    res.json({
      message: "Login successful",
      token
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// =============================
// UPDATE USERNAME
// =============================
app.post("/update-username", verifyToken, async (req, res) => {
  try {
    const { username } = req.body;

    if (!username)
      return res.status(400).json({ message: "Username required" });

    await User.findByIdAndUpdate(req.user.id, { username });

    res.json({ message: "Username updated successfully" });

  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// =============================
// UPDATE PASSWORD
// =============================
app.post("/update-password", verifyToken, async (req, res) => {
  try {
    const { password } = req.body;

    if (!password)
      return res.status(400).json({ message: "Password required" });

    const hashedPassword = await bcrypt.hash(password, 10);

    await User.findByIdAndUpdate(req.user.id, {
      password: hashedPassword
    });

    res.json({ message: "Password updated successfully" });

  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// =============================
// CREATE ORDER
// =============================
app.post("/create-order", verifyToken, async (req, res) => {
  try {
    const { items } = req.body;

    if (!items || items.length === 0)
      return res.status(400).json({ message: "No items provided" });

    let total = 0;

    items.forEach(item => {
      total += item.price * item.quantity;
    });

    const newOrder = new Order({
      userId: req.user.id,
      items,
      totalAmount: total
    });

    await newOrder.save();

    res.json({ message: "Order placed successfully" });

  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// =============================
// GET MY ORDERS (Newest First)
// =============================
app.get("/my-orders", verifyToken, async (req, res) => {
  try {
    const orders = await Order.find({
      userId: req.user.id
    }).sort({ createdAt: -1 });

    res.json(orders);

  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// =============================
// HEALTH CHECK
// =============================
app.get("/", (req, res) => {
  res.send("Backend is running ✅");
});

// =============================
// START SERVER
// =============================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
