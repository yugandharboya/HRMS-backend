const { getUsers } = require("../controllers/userController");
const authenticateToken = require("../middleware/authenticateToken");
const express = require("express");
const router = express.Router();

router.get("/", authenticateToken, getUsers);

module.exports = router;
