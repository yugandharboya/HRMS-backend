const { getDB } = require("../db/connection");

const getUsers = async (req, res) => {
  try {
    const db = getDB();

    const [users] = await db.query("SELECT * FROM users");

    res.status(200).json(users);
  } catch (err) {
    console.error("Get Users Error:", err);
    res.status(500).json({
      message: "Server Error",
    });
  }
};

module.exports = {
  getUsers,
};
