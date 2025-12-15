const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const nodemailer = require("nodemailer");
require("dotenv").config();
require("./Configuration");

const app = express();

/* ===================== MIDDLEWARE ===================== */
app.use(bodyParser.json());
app.use(
  cors({
    origin: ["http://localhost:3000"],
    credentials: true,
  })
);
app.use(cookieParser());

/* ===================== MODELS ===================== */
const RegisterUserModel = require("./models/RegisterUser");
const PersonalInfoModel = require("./models/PersonalInfo");
const AttendanceModel = require("./models/Attendance");
const EmployeeInfoModel = require("./models/Employee");
const TaskModel = require("./models/Task");
const EarnedLeaveEmployeeModel = require("./models/EarnedLeaveRequest");
const LeaveEmployeeModel = require("./models/LeaveRequests");
const UserTaskModel = require("./models/UserTask");

/* ===================== AUTH ===================== */

app.post("/register", async (req, res) => {
  try {
    const { username, email, password, mono } = req.body;

    const existingUser = await RegisterUserModel.findOne({ email });
    if (existingUser)
      return res.status(400).json({ error: "User already exists" });

    const hash = await bcrypt.hash(password, 10);

    const user = await RegisterUserModel.create({
      username,
      email,
      password: hash,
      mono,
      is_admin: 0,
    });

    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await RegisterUserModel.findOne({ email });

    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { email: user.email, is_admin: user.is_admin },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.cookie("token", token, { httpOnly: true });

    res.json({
      token,
      dashboard: user.is_admin ? "adminDashboard" : "userDashboard",
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ===================== FORGOT PASSWORD ===================== */

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  const user = await RegisterUserModel.findOne({ email });

  if (!user) return res.json({ Status: "User not existed" });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: "1d",
  });

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Reset Password",
    text: `http://localhost:3000/reset_password/${user._id}/${token}`,
  });

  res.json({ Status: "Success" });
});

app.post("/reset-password/:id/:token", async (req, res) => {
  try {
    jwt.verify(req.params.token, process.env.JWT_SECRET);
    const hash = await bcrypt.hash(req.body.password, 10);

    await RegisterUserModel.findByIdAndUpdate(req.params.id, {
      password: hash,
    });

    res.json({ Status: "Success" });
  } catch {
    res.status(400).json({ message: "Invalid token" });
  }
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logged out" });
});

/* ===================== SERVER ===================== */

const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on http://localhost:${PORT}`)
);
