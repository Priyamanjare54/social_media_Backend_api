const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { CustomError } = require("../middlewares/error");

/* ================= REGISTER ================= */
const registerController = async (req, res, next) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      throw new CustomError("All fields are required", 400);
    }

    const existingUser = await User.findOne({
      $or: [{ username }, { email }],
    });

    if (existingUser) {
      throw new CustomError("Username or email already exists!", 400);
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
    });

    const savedUser = await newUser.save();
    const { password: _, ...data } = savedUser._doc;

    res.status(201).json(data);
  } catch (error) {
    next(error);
  }
};

/* ================= LOGIN ================= */
const loginController = async (req, res, next) => {
  try {
    const { email, username, password } = req.body;

    const user = email
      ? await User.findOne({ email })
      : await User.findOne({ username });

    if (!user) {
      throw new CustomError("User not found!", 404);
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      throw new CustomError("Wrong credentials!", 401);
    }

    const token = jwt.sign(
      { _id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE }
    );

    const { password: _, ...data } = user._doc;

    res
      .cookie("token", token, {
        httpOnly: true,
        sameSite: "lax",
        secure: false, // true in production (HTTPS)
      })
      .status(200)
      .json(data);
  } catch (error) {
    next(error);
  }
};

/* ================= LOGOUT ================= */
const logoutController = async (req, res, next) => {
  try {
    res
      .clearCookie("token", {
        httpOnly: true,
        sameSite: "lax",
        secure: false,
      })
      .status(200)
      .json("User logged out successfully!");
  } catch (error) {
    next(error);
  }
};

/* ================= REFRESH USER ================= */
const refetchUserController = async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      throw new CustomError("Not authenticated", 401);
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded._id).select("-password");

    res.status(200).json(user);
  } catch (error) {
    next(error);
  }
};

module.exports = {
  registerController,
  loginController,
  logoutController,
  refetchUserController,
};
