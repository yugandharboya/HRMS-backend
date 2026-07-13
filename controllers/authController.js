const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { getDB } = require("../db/connection");

// Register
const register = async (req, res) => {
  const db = getDB();
  const { orgName, adminName, email, password } = req.body;

  try {
    // Check if email already exists
    const [existingUsers] = await db.query(
      "SELECT * FROM users WHERE email = ?",
      [email],
    );

    if (existingUsers.length > 0) {
      return res.status(400).json({
        message: "Email already exists",
      });
    }

    // Create organization
    const [orgResult] = await db.query(
      "INSERT INTO organisations (name) VALUES (?)",
      [orgName],
    );

    const orgId = orgResult.insertId;

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create admin user
    const [userResult] = await db.query(
      `INSERT INTO users
      (organisation_id, email, password_hash, name)
      VALUES (?, ?, ?, ?)`,
      [orgId, email, hashedPassword, adminName],
    );

    const userId = userResult.insertId;

    // Generate JWT
    const token = jwt.sign(
      {
        userId,
        orgId,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "24h",
      },
    );

    res.status(201).json({
      token,
      user: {
        id: userId,
        name: adminName,
        email,
        organisation_id: orgId,
      },
    });
  } catch (err) {
    console.log("Register Error:", err);
    res.status(500).json({
      message: "Server Error",
    });
  }
};

// Login
const login = async (req, res) => {
  const db = getDB();
  const { email, password } = req.body;

  try {
    // Find user
    const [users] = await db.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);

    if (users.length === 0) {
      return res.status(401).json({
        message: "Invalid email or password",
      });
    }

    const user = users[0];

    // Compare password
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);

    if (!isPasswordValid) {
      return res.status(401).json({
        message: "Invalid email or password",
      });
    }

    // Generate JWT
    const token = jwt.sign(
      {
        userId: user.id,
        orgId: user.organisation_id,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "24h",
      },
    );

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        organisation_id: user.organisation_id,
      },
    });
  } catch (err) {
    console.log("Login Error:", err);
    res.status(500).json({
      message: "Server Error",
    });
  }
};

module.exports = {
  register,
  login,
};
