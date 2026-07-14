const express = require("express");
const authenticateToken = require("../middleware/authenticateToken");

const {
  addTeam,
  getTeams,
  getTeamById,
  updateTeam,
  deleteTeam,
  assignEmployeeToTeam,
  unassignEmployeeFromTeam,
  getTeamMembers,
  getAssignedMembers,
} = require("../controllers/teamController");

const router = express.Router();

router.post("/", authenticateToken, addTeam);

router.get("/", authenticateToken, getTeams);

// Static route first
router.get("/assigned_members/all", authenticateToken, getAssignedMembers);

// Dynamic routes
router.post("/:teamId/assign_team", authenticateToken, assignEmployeeToTeam);

router.delete("/:teamId/unassign", authenticateToken, unassignEmployeeFromTeam);
router.delete("/:teamId/unassign/:employeeId", authenticateToken, unassignEmployeeFromTeam);

router.get("/:teamId/members", authenticateToken, getTeamMembers);

router.get("/:id", authenticateToken, getTeamById);

router.put("/:id", authenticateToken, updateTeam);

router.delete("/:id", authenticateToken, deleteTeam);

module.exports = router;
