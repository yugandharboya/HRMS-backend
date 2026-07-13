const { getUsers } = require("../controllers/userController");
const express = require("express");
const router = express.Router();

router.get("/", getUsers);

module.exports = router;
