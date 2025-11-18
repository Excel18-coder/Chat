import bcrypt from "bcryptjs";
import { generateToken } from "../lib/utils.js";
import User from "../models/User.js";

export const signup = async (req, res) => {
  // Accept either `fullName` (typical front-end key) or `FullName` (legacy)
  const { FullName, fullName, email, password } = req.body;
  const name = fullName || FullName;

  try {
    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({ message: "Password must be at least six characters" });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    const user = await User.findOne({ email });
    if (user) return res.status(400).json({ message: "Email already exists" });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Save using the model's field name (FullName) to avoid breaking existing docs
    const newUser = new User({
      FullName: name,
      email,
      password: hashedPassword,
    });

    await newUser.save();

    // Generate token after saving (so _id exists)
    generateToken(newUser._id, res);

    res.status(201).json({
      _id: newUser._id,
      // return a consistent client-facing key
      fullName: newUser.FullName,
      email: newUser.email,
      profilePic: newUser.profilepic,
    });
  } catch (error) {
    console.log("Error in signup controller:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};
