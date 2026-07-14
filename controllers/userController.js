const { getDB } = require("../db/connection");

const getUsers = async (req, res) => {
  try {
    const db = getDB();
    const { orgId } = req.user;

    const [users] = await db.query(
      "SELECT id, organisation_id, email, name, created_at FROM users WHERE organisation_id = ?",
      [orgId]
    );

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
