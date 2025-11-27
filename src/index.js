const express = require("express");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const path = require("path");
const dbPath = path.join(__dirname, "users.db");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();
app.use(express.json());
app.use(cors());

let db = null;
const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    const createTables = async () => {
      await db.exec(`CREATE TABLE IF NOT EXISTS organisations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );`);
      await db.exec(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organisation_id INTEGER,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (organisation_id) REFERENCES organisations(id)
  );`);
      await db.exec(`CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organisation_id INTEGER,
    first_name TEXT,
    last_name TEXT,
    email TEXT,
    phone TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (organisation_id) REFERENCES organisations(id)
  );`);

      // await db.exec(`DROP TABLE IF EXISTS teams;`);
      await db.exec(`CREATE TABLE IF NOT EXISTS teams (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  organisation_id INTEGER,
  name TEXT NOT NULL,
  description TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (organisation_id) REFERENCES organisations(id),
  UNIQUE (organisation_id, name)
);`);

      await db.exec(`CREATE TABLE IF NOT EXISTS employee_teams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER,
    team_id INTEGER,
    assigned_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
    FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE
  );`);
      await db.exec(`CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organisation_id INTEGER,
    user_id INTEGER,
    action TEXT,
    meta TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP
  );`);
    };
    await createTables();

    const PORT = process.env.PORT || 5000;

    app.listen(PORT, () => {
      console.log(`Server Running at port ${PORT}`);
    });
  } catch (e) {
    console.log(`DB Error: ${e.message}`);
    process.exit(1);
  }
};
initializeDbAndServer();
app.post("/auth/register", async (req, res) => {
  const { orgName, adminName, email, password } = req.body;

  try {
    // 1. Check if email already exists
    const userExist = await db.get(`SELECT * FROM users WHERE email = ?`, [
      email,
    ]);
    if (userExist) {
      return res.status(400).send("Email already exists");
    }

    const orgResult = await db.run(
      `INSERT INTO organisations (name) VALUES (?)`,
      [orgName]
    );
    const orgId = orgResult.lastID;

    // 3. Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 4. Create admin user
    const userResult = await db.run(
      `INSERT INTO users (organisation_id, email, password_hash, name)
       VALUES (?, ?, ?, ?)`,
      [orgId, email, hashedPassword, adminName]
    );
    const userId = userResult.lastID;

    // 5. Generate JWT
    const token = jwt.sign({ userId: userId, orgId: orgId }, "SECRET_KEY", {
      expiresIn: "24h",
    });

    // 6. Respond
    res.json({
      token,
      user: {
        id: userId,
        name: adminName,
        email: email,
        organisation_id: orgId,
      },
    });
  } catch (error) {
    console.log("Register Error:", error);
    res.status(500).send("Server Error");
  }
});
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    // 1. Find user by email
    const user = await db.get(`SELECT * FROM users WHERE email = ?`, [email]);
    if (!user) {
      return res.status(401).send("Invalid email or password");
    }
    // 2. Compare password
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) {
      return res.status(400).send("Invalid email or password");
    }
    // 3. Generate JWT
    const token = jwt.sign(
      { userId: user.id, orgId: user.organisation_id },
      "SECRET_KEY",
      { expiresIn: "24h" }
    );
    // 4. Respond
    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        organisation_id: user.organisation_id,
      },
    });
  } catch (error) {
    console.log("Login Error:", error);
    res.status(500).send("Server Error");
  }
});

const authenticateToken = (request, response, next) => {
  let jwtToken;
  const authHeader = request.headers["authorization"];
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(" ")[1];
  }

  if (jwtToken === undefined) {
    response.status(401);
    response.send("Invalid JWT Token");
  } else {
    jwt.verify(jwtToken, "SECRET_KEY", async (error, payload) => {
      if (error) {
        response.status(401);
        response.send("Invalid JWT Token");
      } else {
        request.user = payload;
        next();
      }
    });
  }
};

// Add new team
app.post("/teams", authenticateToken, async (request, response) => {
  const { orgId } = request.user;
  const { name, description } = request.body;
  try {
    const result = await db.run(
      `INSERT INTO teams (organisation_id, name, description) VALUES (?, ?, ?)`,
      [orgId, name, description || null]
    );
    const teamId = result.lastID;
    const team = await db.get(`SELECT * FROM teams WHERE id = ?`, [teamId]);
    response.status(201).json(team);
  } catch (err) {
    console.log("Create Team Error:", err);
    response.status(500).json({ error: "Server error" });
  }
});

// get all teams of an organization
app.get("/teams", authenticateToken, async (req, res) => {
  const { orgId } = req.user;
  try {
    const teams = await db.all(
      `SELECT * FROM teams WHERE organisation_id = ?`,
      [orgId]
    );
    res.json(teams);
  } catch (err) {
    console.log("Get Teams Error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/employees", authenticateToken, async (req, res) => {
  const { orgId } = req.user;
  const { firstName, lastName, email, phone } = req.body;

  try {
    const result = await db.run(
      `INSERT INTO employees (organisation_id, first_name, last_name, email, phone)
       VALUES (?, ?, ?, ?, ?)`,
      [orgId, firstName, lastName, email, phone]
    );
    const employeeId = result.lastID;
    const newEmployee = await db.get(`SELECT * FROM employees WHERE id = ?`, [
      employeeId,
    ]);
    res.status(201).json(newEmployee);
  } catch (error) {
    console.log("Seed Error:", error);
    res.status(500).send("Server Error");
  }
});

// get all employees of an organization
app.get("/employees", authenticateToken, async (req, res) => {
  const { orgId } = req.user;
  try {
    const employees = await db.all(
      `SELECT * FROM employees WHERE organisation_id = ?`,
      [orgId]
    );
    res.json(employees);
  } catch (error) {
    console.log("Get Employees Error:", error);
    res.status(500).send("Server Error");
  }
});

// Get employee by ID
app.get("/employees/:id", authenticateToken, async (req, res) => {
  const { orgId } = req.user;
  const { id } = req.params;
  try {
    const employeeExist = await db.get(
      `SELECT * FROM employees WHERE id = ? AND organisation_id = ?`,
      [id, orgId]
    );
    if (!employeeExist) {
      return res.status(404).send("Employee not found");
    }
    res.json(employeeExist);
  } catch (error) {
    console.log("Get Employee Error:", error);
    res.status(500).send("Server Error");
  }
});
// Update employee by ID
app.put("/employees/:id", authenticateToken, async (req, res) => {
  const { orgId } = req.user;
  const { id } = req.params;
  const { firstName, lastName, email, phone } = req.body;
  try {
    const employeeExist = await db.get(
      `SELECT * FROM employees WHERE id = ? AND organisation_id = ?`,
      [id, orgId]
    );
    if (!employeeExist) {
      return res.status(404).send("Employee not found");
    }
    await db.run(
      `UPDATE employees
       SET first_name = ?, last_name = ?, email = ?, phone = ?
       WHERE id = ? AND organisation_id = ?`,
      [firstName, lastName, email, phone, id, orgId]
    );
    res.send("Employee updated successfully");
  } catch (error) {
    console.log("Update Employee Error:", error);
    res.status(500).send("Server Error");
  }
});
// Delete employee by ID
app.delete("/employees/:id", authenticateToken, async (req, res) => {
  const { orgId } = req.user;
  const { id } = req.params;
  try {
    const employeeExist = await db.get(
      `SELECT * FROM employees WHERE id = ? AND organisation_id = ?`,
      [id, orgId]
    );
    if (!employeeExist) {
      return res.status(404).send("Employee not found");
    }
    await db.run(`DELETE FROM employees WHERE id = ? AND organisation_id = ?`, [
      id,
      orgId,
    ]);
    res.send("Employee deleted successfully");
  } catch (error) {
    console.log("Delete Employee Error:", error);
    res.status(500).send("Server Error");
  }
});

// routs for teams
app.post("/teams", authenticateToken, async (req, res) => {
  try {
    const { name, description } = req.body;
    const orgId = req.user.orgId;
    if (!name) return res.status(400).json({ error: "name required" });
    const result = await db.run(
      `INSERT INTO teams (organisation_id, name, description) VALUES (?, ?, ?)`,
      [orgId, name, description || null]
    );
    const teamId = result.lastID;
    const team = await db.get(`SELECT * FROM teams WHERE id = ?`, [teamId]);
    res.status(201).json(team);
  } catch (err) {
    console.log("Create Team Error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/teams", authenticateToken, async (req, res) => {
  try {
    const orgId = req.user.orgId;
    const teams = await db.all(
      `SELECT * FROM teams WHERE organisation_id = ?`,
      [orgId]
    );
    res.json(teams);
  } catch (err) {
    console.log("Get Teams Error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/teams/:id", authenticateToken, async (req, res) => {
  try {
    const orgId = req.user.orgId;
    const { id } = req.params;
    const team = await db.get(
      `SELECT * FROM teams WHERE id = ? AND organisation_id = ?`,
      [id, orgId]
    );
    if (!team) return res.status(404).send("Team not found");
    res.json(team);
  } catch (err) {
    console.log("Get Team Error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.put("/teams/:id", authenticateToken, async (req, res) => {
  try {
    const orgId = req.user.orgId;
    const { id } = req.params;
    const { name, description } = req.body;
    const teamExist = await db.get(
      `SELECT * FROM teams WHERE id = ? AND organisation_id = ?`,
      [id, orgId]
    );
    if (!teamExist) return res.status(404).send("Team not found");
    await db.run(
      `UPDATE teams SET name = ?, description = ? WHERE id = ? AND organisation_id = ?`,
      [name || teamExist.name, description || teamExist.description, id, orgId]
    );
    const updated = await db.get(`SELECT * FROM teams WHERE id = ?`, [id]);
    res.json(updated);
  } catch (err) {
    console.log("Update Team Error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.delete("/teams/:id", authenticateToken, async (req, res) => {
  try {
    const orgId = req.user.orgId;
    const { id } = req.params;
    const teamExist = await db.get(
      `SELECT * FROM teams WHERE id = ? AND organisation_id = ?`,
      [id, orgId]
    );
    if (!teamExist) return res.status(404).send("Team not found");
    await db.run(`DELETE FROM teams WHERE id = ? AND organisation_id = ?`, [
      id,
      orgId,
    ]);
    res.send("Team deleted successfully");
  } catch (err) {
    console.log("Delete Team Error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Assign employee to a team
app.post("/teams/:teamId/assign", authenticateToken, async (req, res) => {
  try {
    const { teamId } = req.params;
    const { employeeId } = req.body;
    const orgId = req.user.orgId;

    const team = await db.get(
      `SELECT * FROM teams WHERE id = ? AND organisation_id = ?`,
      [teamId, orgId]
    );
    if (!team) return res.status(404).send("Team not found");

    const employee = await db.get(
      `SELECT * FROM employees WHERE id = ? AND organisation_id = ?`,
      [employeeId, orgId]
    );
    if (!employee) return res.status(404).send("Employee not found");

    const exists = await db.get(
      `SELECT id FROM employee_teams WHERE employee_id = ? AND team_id = ?`,
      [employeeId, teamId]
    );
    if (exists) return res.status(409).send("Already assigned");

    await db.run(
      `INSERT INTO employee_teams (employee_id, team_id) VALUES (?, ?)`,
      [employeeId, teamId]
    );

    res.send("Employee assigned to team");
  } catch (err) {
    console.log("Assign Error:", err);
    res.status(500).send("Server Error");
  }
});

// Unassign employee from a team
app.delete("/teams/:teamId/unassign", authenticateToken, async (req, res) => {
  try {
    const { teamId } = req.params;
    const { employeeId } = req.body;
    const orgId = req.user.orgId;

    const team = await db.get(
      `SELECT * FROM teams WHERE id = ? AND organisation_id = ?`,
      [teamId, orgId]
    );
    if (!team) return res.status(404).send("Team not found");

    const employee = await db.get(
      `SELECT * FROM employees WHERE id = ? AND organisation_id = ?`,
      [employeeId, orgId]
    );
    if (!employee) return res.status(404).send("Employee not found");

    await db.run(
      `DELETE FROM employee_teams WHERE employee_id = ? AND team_id = ?`,
      [employeeId, teamId]
    );

    res.send("Employee unassigned from team");
  } catch (err) {
    console.log("Unassign Error:", err);
    res.status(500).send("Server Error");
  }
});

// Get all employees in a team
app.get("/teams/:teamId/members", authenticateToken, async (req, res) => {
  try {
    const { teamId } = req.params;
    const orgId = req.user.orgId;

    const team = await db.get(
      `SELECT * FROM teams WHERE id = ? AND organisation_id = ?`,
      [teamId, orgId]
    );
    if (!team) return res.status(404).send("Team not found");

    const members = await db.all(
      `SELECT e.* 
       FROM employees e
       JOIN employee_teams et ON e.id = et.employee_id
       WHERE et.team_id = ? AND e.organisation_id = ?`,
      [teamId, orgId]
    );

    res.json(members);
  } catch (err) {
    console.log("Get Members Error:", err);
    res.status(500).send("Server Error");
  }
});

// Get all teams for an employee
app.get("/employees/:employeeId/teams", authenticateToken, async (req, res) => {
  try {
    const { employeeId } = req.params;
    const orgId = req.user.orgId;

    const employee = await db.get(
      `SELECT * FROM employees WHERE id = ? AND organisation_id = ?`,
      [employeeId, orgId]
    );
    if (!employee) return res.status(404).send("Employee not found");

    const teams = await db.all(
      `SELECT t.*
       FROM teams t
       JOIN employee_teams et ON t.id = et.team_id
       WHERE et.employee_id = ? AND t.organisation_id = ?`,
      [employeeId, orgId]
    );

    res.json(teams);
  } catch (err) {
    console.log("Get Teams Error:", err);
    res.status(500).send("Server Error");
  }
});
