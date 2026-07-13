const express = require("express");

const router = express.Router();
const authenticateToken = require("../middleware/authenticateToken");

const {
  addEmployee,
  getEmployees,
  getEmployeeById,
  updateEmployee,
  deleteEmployee,
} = require("../controllers/employeeController");

router.post("/", authenticateToken, addEmployee);

router.get("/", authenticateToken, getEmployees);

router.get("/:id", authenticateToken, getEmployeeById);

router.put("/:id", authenticateToken, updateEmployee);

router.delete("/:id", authenticateToken, deleteEmployee);

module.exports = router;
