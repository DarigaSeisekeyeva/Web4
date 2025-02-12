const express = require("express");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const User = require("../models/User");

const router = express.Router();

const uploadDir = "public/uploads";
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: uploadDir,
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({ storage });

router.get("/register", (req, res) => {
  res.render("register", { error: null });
});

router.post("/register", upload.single("profilePicture"), async (req, res) => {
  const { username, email, password } = req.body;
  
  if (!username || !email || !password) {
    return res.render("register", { error: "All fields are required" });
  }

  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
  if (!passwordRegex.test(password)) {
    return res.render("register", { 
      error: "Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a number, and a special character." 
    });
  }

  try {
    let user = await User.findOne({ email });
    if (user) return res.render("register", { error: "User already exists" });

    const profilePicture = req.file ? "/uploads/" + req.file.filename : "/uploads/profile.jpg";
    
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user = new User({ username, email, password: hashedPassword, profilePicture });
    await user.save();
    res.redirect("/login");
  } catch (err) {
    console.error(err);
    res.status(500).render("register", { error: "Server error" });
  }
});

const loginAttempts = {};
router.get("/logout", (req, res) => {
  req.session.destroy((err) => {
      if (err) {
          console.error("Logout error:", err);
          return res.status(500).send("Error logging out");
      }
      res.redirect("/login");
  });
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.render("login", { error: "All fields are required" });
  }

  if (loginAttempts[email] && loginAttempts[email].blockedUntil > Date.now()) {
    return res.render("login", { error: "Too many failed attempts. Try again later." });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) return res.render("login", { error: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      if (!loginAttempts[email]) loginAttempts[email] = { count: 0, blockedUntil: null };
      loginAttempts[email].count++;
      if (loginAttempts[email].count >= 5) {
        loginAttempts[email].blockedUntil = Date.now() + 15 * 60 * 1000;
      }
      return res.render("login", { error: "Invalid credentials" });
    }

    delete loginAttempts[email];
    req.session.user = user;
    res.redirect("/dashboard");
  } catch (err) {
    console.error(err);
    res.status(500).render("login", { error: "Server error" });
  }
});
router.get("/login", (req, res) => {
    res.render("login", { error: null });
  });
  
router.get("/profile", async (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login");
  }

  try {
    const user = await User.findById(req.session.user._id).select("-password");
    res.render("profile", { user });
  } catch (err) {
    console.error("Error fetching profile:", err);
    res.status(500).send("Server error");
  }
});
router.post("/upload-profile", upload.single("profilePicture"), async (req, res) => {
    if (!req.session.user) {
      return res.status(401).json({ error: "Unauthorized" });
    }
  
    try {
      const user = await User.findById(req.session.user._id);
      if (!user) return res.status(404).json({ error: "User not found" });
  
      user.profilePicture = "/uploads/" + req.file.filename;
      await user.save();
  
      req.session.user.profilePicture = user.profilePicture;
      res.redirect("/profile");
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Server error" });
    }
  });
  router.post("/profile/edit", upload.single("profilePicture"), async (req, res) => {
    if (!req.session.user) {
      return res.status(401).json({ error: "Unauthorized" });
    }
  
    try {
      const user = await User.findById(req.session.user._id);
      if (!user) return res.status(404).json({ error: "User not found" });
  
      if (req.body.username) {
        user.username = req.body.username;
      }
  
      if (req.body.email) {
        user.email = req.body.email;
      }
  
      if (req.file) {
        user.profilePicture = "/uploads/" + req.file.filename;
      }
  
      await user.save();
  
      req.session.user.username = user.username;
      req.session.user.profilePicture = user.profilePicture;
  
      res.redirect("/profile");
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Server error" });
    }
  });
  router.post("/profile/delete", async (req, res) => {
    if (!req.session.user) {
      return res.status(401).json({ error: "Unauthorized" });
    }
  
    try {
      await User.findByIdAndDelete(req.session.user._id);
      req.session.destroy(); 
      res.redirect("/register");
    } catch (err) {
      console.error("Error deleting profile:", err);
      res.status(500).json({ error: "Server error" });
    }
  });
  
module.exports = router;
