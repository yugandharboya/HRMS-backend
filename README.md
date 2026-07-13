# HRMS Backend

A RESTful backend API for the Human Resource Management System (HRMS) built using Node.js, Express.js, and MySQL.

---

## Tech Stack

- Node.js
- Express.js
- MySQL (Railway)
- JWT Authentication
- bcrypt
- dotenv

---

## Features

- User Registration
- User Login
- JWT Authentication
- Employee Management (CRUD)
- Team Management (CRUD)
- Assign Employees to Teams
- Unassign Employees from Teams
- Get Team Members
- Get Assigned Members
- Multi-Organization Support

---

## Project Structure

```text
backend/
│
├── src/
│   ├── controllers/
│   │   ├── authController.js
│   │   ├── userController.js
│   │   ├── employeeController.js
│   │   └── teamController.js
│   │
│   ├── routes/
│   │   ├── authRoutes.js
│   │   ├── userRoutes.js
│   │   ├── employeeRoutes.js
│   │   └── teamRoutes.js
│   │
│   ├── middleware/
│   │   └── authenticateToken.js
│   │
│   ├── db/
│   │   ├── connection.js
│   │   └── createTables.js
│   │
│   └── server.js
│
├── .env
├── package.json
└── README.md
```

---

## Database Tables

- organisations
- users
- employees
- teams
- employee_teams

---

## API Endpoints

### Authentication

- POST `/auth/register`
- POST `/auth/login`

### Users

- GET `/users`

### Employees

- POST `/employees`
- GET `/employees`
- GET `/employees/:id`
- PUT `/employees/:id`
- DELETE `/employees/:id`

### Teams

- POST `/teams`
- GET `/teams`
- GET `/teams/:id`
- PUT `/teams/:id`
- DELETE `/teams/:id`

### Team Assignment

- POST `/teams/:teamId/assign_team`
- DELETE `/teams/:teamId/unassign`
- GET `/teams/:teamId/members`
- GET `/teams/assigned_members/all`

---

## Installation

Clone the repository:

```bash
git clone <repository-url>
```

Install dependencies:

```bash
npm install
```

Create a `.env` file:

```env
PORT=5000

MYSQLHOST=your_host
MYSQLPORT=your_port
MYSQLDATABASE=your_database
MYSQLUSER=your_user
MYSQLPASSWORD=your_password

JWT_SECRET=your_secret_key
```

Start the development server:

```bash
npm run dev
```

---

## Authentication

Protected routes require a JWT token.

Example:

```http
Authorization: Bearer <your_jwt_token>
```

---

## Author

**Yugandhar Boya**