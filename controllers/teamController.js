const { getDB } = require("../db/connection");

// Add Team
const addTeam = async (req, res) => {
  const db = getDB();
  const { orgId } = req.user;
  const { name, description } = req.body;

  try {
    const [teams] = await db.query(
      "SELECT * FROM teams WHERE name = ? AND organisation_id = ?",
      [name, orgId],
    );

    if (teams.length > 0) {
      return res.status(400).json({
        message: "Team with this name already exists",
      });
    }

    const [result] = await db.query(
      "INSERT INTO teams (organisation_id, name, description) VALUES (?, ?, ?)",
      [orgId, name, description || null],
    );

    const [team] = await db.query("SELECT * FROM teams WHERE id = ?", [
      result.insertId,
    ]);

    res.status(201).json(team[0]);
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Server Error" });
  }
};

// Get All Teams
const getTeams = async (req, res) => {
  const db = getDB();
  const { orgId } = req.user;

  try {
    const [teams] = await db.query(
      "SELECT * FROM teams WHERE organisation_id = ?",
      [orgId],
    );

    res.json(teams);
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Server Error" });
  }
};

// Get Team By Id
const getTeamById = async (req, res) => {
  const db = getDB();
  const { orgId } = req.user;
  const { id } = req.params;

  try {
    const [teams] = await db.query(
      "SELECT * FROM teams WHERE id = ? AND organisation_id = ?",
      [id, orgId],
    );

    if (teams.length === 0) {
      return res.status(404).json({
        message: "Team not found",
      });
    }

    res.json(teams[0]);
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Server Error" });
  }
};

// Update Team
const updateTeam = async (req, res) => {
  const db = getDB();
  const { orgId } = req.user;
  const { id } = req.params;
  const { name, description } = req.body;

  try {
    const [teams] = await db.query(
      "SELECT * FROM teams WHERE id = ? AND organisation_id = ?",
      [id, orgId],
    );

    if (teams.length === 0) {
      return res.status(404).json({
        message: "Team not found",
      });
    }

    await db.query(
      `UPDATE teams
       SET name = ?, description = ?
       WHERE id = ? AND organisation_id = ?`,
      [name || teams[0].name, description || teams[0].description, id, orgId],
    );

    const [updatedTeam] = await db.query("SELECT * FROM teams WHERE id = ?", [
      id,
    ]);

    res.json(updatedTeam[0]);
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Server Error" });
  }
};

// Delete Team
const deleteTeam = async (req, res) => {
  const db = getDB();
  const { orgId } = req.user;
  const { id } = req.params;

  try {
    const [teams] = await db.query(
      "SELECT * FROM teams WHERE id = ? AND organisation_id = ?",
      [id, orgId],
    );

    if (teams.length === 0) {
      return res.status(404).json({
        message: "Team not found",
      });
    }

    await db.query("DELETE FROM teams WHERE id = ? AND organisation_id = ?", [
      id,
      orgId,
    ]);

    res.json({
      message: "Team deleted successfully",
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Server Error" });
  }
};
const assignEmployeeToTeam = async (req, res) => {
  const db = getDB();
  const { teamId } = req.params;
  const { employeeId } = req.body;
  const { orgId } = req.user;

  try {
    const [teams] = await db.query(
      "SELECT * FROM teams WHERE id = ? AND organisation_id = ?",
      [teamId, orgId],
    );

    if (teams.length === 0) {
      return res.status(404).json({ message: "Team not found" });
    }

    const [employees] = await db.query(
      "SELECT * FROM employees WHERE id = ? AND organisation_id = ?",
      [employeeId, orgId],
    );

    if (employees.length === 0) {
      return res.status(404).json({ message: "Employee not found" });
    }

    const [existing] = await db.query(
      `SELECT id FROM employee_teams
       WHERE employee_id = ? AND team_id = ? AND organisation_id = ?`,
      [employeeId, teamId, orgId],
    );

    if (existing.length > 0) {
      return res.status(409).json({
        message: "Already assigned",
      });
    }

    await db.query(
      `INSERT INTO employee_teams
      (employee_id, team_id, organisation_id)
      VALUES (?, ?, ?)`,
      [employeeId, teamId, orgId],
    );

    res.json({
      message: "Employee assigned to team",
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({
      message: "Server Error",
    });
  }
};
const unassignEmployeeFromTeam = async (req, res) => {
  const db = getDB();
  const { teamId } = req.params;
  const { employeeId } = req.body;
  const { orgId } = req.user;

  try {
    const [assignment] = await db.query(
      `SELECT id
       FROM employee_teams
       WHERE employee_id = ?
       AND team_id = ?
       AND organisation_id = ?`,
      [employeeId, teamId, orgId],
    );

    if (assignment.length === 0) {
      return res.status(404).json({
        message: "Assignment not found",
      });
    }

    await db.query(
      `DELETE FROM employee_teams
       WHERE employee_id = ?
       AND team_id = ?
       AND organisation_id = ?`,
      [employeeId, teamId, orgId],
    );

    res.json({
      message: "Employee unassigned from team",
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({
      message: "Server Error",
    });
  }
};
const getTeamMembers = async (req, res) => {
  const db = getDB();
  const { teamId } = req.params;
  const { orgId } = req.user;

  try {
    const [members] = await db.query(
      `SELECT e.*
       FROM employees e
       JOIN employee_teams et
       ON e.id = et.employee_id
       WHERE et.team_id = ?
       AND et.organisation_id = ?`,
      [teamId, orgId],
    );

    res.json(members);
  } catch (err) {
    console.log(err);
    res.status(500).json({
      message: "Server Error",
    });
  }
};
const getAssignedMembers = async (req, res) => {
  const db = getDB();
  const { orgId } = req.user;

  try {
    const [assignedMembers] = await db.query(
      `SELECT *
       FROM employee_teams
       WHERE organisation_id = ?`,
      [orgId],
    );

    res.json(assignedMembers);
  } catch (err) {
    console.log(err);
    res.status(500).json({
      message: "Server Error",
    });
  }
};

module.exports = {
  addTeam,
  getTeams,
  getTeamById,
  updateTeam,
  deleteTeam,
  assignEmployeeToTeam,
  unassignEmployeeFromTeam,
  getTeamMembers,
  getAssignedMembers,
};
