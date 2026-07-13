require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { initializeDB } = require("./db/connection");
const authRoutes = require("./routes/authRoutes");
const userRoutes = require("./routes/userRoutes");
const employeeRoutes = require("./routes/employeeRoutes");
const teamRoutes = require("./routes/teamRoutes");

const app = express();
app.use(express.json());

app.use(cors());
app.use("/users", userRoutes);
app.use("/auth", authRoutes);
app.use("/employees", employeeRoutes);
app.use("/teams", teamRoutes);

const startServer = async () => {
  try {
    await initializeDB();

    app.listen(process.env.PORT || 5000, () => {
      console.log(`🚀 Server running...`);
    });
  } catch (err) {
    console.error("Server Error:", err);
    process.exit(1);
  }
};

startServer();
