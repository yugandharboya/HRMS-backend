const { getDB } = require("../db/connection");

// Add Employee
const addEmployee = async (req, res) => {
  const db = getDB();
  const { orgId } = req.user;
  const { firstName, lastName, email, phone } = req.body;

  try {
    const [existingEmployees] = await db.query(
      "SELECT * FROM employees WHERE email = ? AND organisation_id = ?",
      [email, orgId],
    );

    if (existingEmployees.length > 0) {
      return res.status(400).json({
        message: "Employee with this email already exists",
      });
    }

    const [result] = await db.query(
      `INSERT INTO employees
      (organisation_id, first_name, last_name, email, phone)
      VALUES (?, ?, ?, ?, ?)`,
      [orgId, firstName, lastName, email, phone],
    );

    const [employee] = await db.query("SELECT * FROM employees WHERE id = ?", [
      result.insertId,
    ]);

    res.status(201).json(employee[0]);
  } catch (err) {
    console.log(err);
    res.status(500).json({
      message: "Server Error",
    });
  }
};

// Get All Employees
const getEmployees = async (req, res) => {
  const db = getDB();
  const { orgId } = req.user;

  try {
    const [employees] = await db.query(
      "SELECT * FROM employees WHERE organisation_id = ?",
      [orgId],
    );

    res.json(employees);
  } catch (err) {
    console.log(err);
    res.status(500).json({
      message: "Server Error",
    });
  }
};

// Get Employee By Id
const getEmployeeById = async (req, res) => {
  const db = getDB();
  const { orgId } = req.user;
  const { id } = req.params;

  try {
    const [employees] = await db.query(
      "SELECT * FROM employees WHERE id = ? AND organisation_id = ?",
      [id, orgId],
    );

    if (employees.length === 0) {
      return res.status(404).json({
        message: "Employee not found",
      });
    }

    res.json(employees[0]);
  } catch (err) {
    console.log(err);
    res.status(500).json({
      message: "Server Error",
    });
  }
};

// Update Employee
const updateEmployee = async (req, res) => {
  const db = getDB();
  const { orgId } = req.user;
  const { id } = req.params;
  const { firstName, lastName, email, phone } = req.body;

  try {
    const [employees] = await db.query(
      "SELECT * FROM employees WHERE id = ? AND organisation_id = ?",
      [id, orgId],
    );

    if (employees.length === 0) {
      return res.status(404).json({
        message: "Employee not found",
      });
    }

    await db.query(
      `UPDATE employees
      SET first_name=?, last_name=?, email=?, phone=?
      WHERE id=? AND organisation_id=?`,
      [firstName, lastName, email, phone, id, orgId],
    );

    res.json({
      message: "Employee updated successfully!",
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({
      message: "Server Error",
    });
  }
};

// Delete Employee
const deleteEmployee = async (req, res) => {
  const db = getDB();
  const { orgId } = req.user;
  const { id } = req.params;

  try {
    const [employees] = await db.query(
      "SELECT * FROM employees WHERE id = ? AND organisation_id = ?",
      [id, orgId],
    );

    if (employees.length === 0) {
      return res.status(404).json({
        message: "Employee not found",
      });
    }

    await db.query(
      "DELETE FROM employees WHERE id = ? AND organisation_id = ?",
      [id, orgId],
    );

    res.json({
      message: "Employee deleted successfully",
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({
      message: "Server Error",
    });
  }
};

module.exports = {
  addEmployee,
  getEmployees,
  getEmployeeById,
  updateEmployee,
  deleteEmployee,
};
