const createTables = async (db) => {
  // Organisations
  await db.query(`
    CREATE TABLE IF NOT EXISTS organisations (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(255) NOT NULL UNIQUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Users
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      organisation_id INT,
      email VARCHAR(255) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      name VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (organisation_id) REFERENCES organisations(id)
        ON DELETE CASCADE
    );
  `);

  // Employees
  await db.query(`
    CREATE TABLE IF NOT EXISTS employees (
      id INT AUTO_INCREMENT PRIMARY KEY,
      organisation_id INT,
      first_name VARCHAR(100),
      last_name VARCHAR(100),
      email VARCHAR(255),
      phone VARCHAR(20),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY unique_employee_email (organisation_id, email),
      FOREIGN KEY (organisation_id) REFERENCES organisations(id)
        ON DELETE CASCADE
    );
  `);

  // Teams
  await db.query(`
    CREATE TABLE IF NOT EXISTS teams (
      id INT AUTO_INCREMENT PRIMARY KEY,
      organisation_id INT,
      name VARCHAR(255) NOT NULL,
      description TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY unique_team_name (organisation_id, name),
      CONSTRAINT chk_team_name CHECK (CHAR_LENGTH(name) > 0),
      FOREIGN KEY (organisation_id) REFERENCES organisations(id)
        ON DELETE CASCADE
    );
  `);

  // Employee Teams
  await db.query(`
    CREATE TABLE IF NOT EXISTS employee_teams (
      id INT AUTO_INCREMENT PRIMARY KEY,
      employee_id INT,
      team_id INT,
      organisation_id INT,
      assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY unique_assignment (employee_id, team_id, organisation_id),
      FOREIGN KEY (employee_id) REFERENCES employees(id)
        ON DELETE CASCADE,
      FOREIGN KEY (team_id) REFERENCES teams(id)
        ON DELETE CASCADE,
      FOREIGN KEY (organisation_id) REFERENCES organisations(id)
        ON DELETE CASCADE
    );
  `);
};

module.exports = createTables;
