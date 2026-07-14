const mysql = require("mysql2/promise");
const createTables = require("./createTables");

let db = null;

const initializeDB = async () => {
  try {
    const dbConfig = {
      host: process.env.MYSQL_HOST || "localhost",
      user: process.env.MYSQL_USER || "root",
      password: process.env.MYSQL_PASSWORD || "",
      database: process.env.MYSQL_DATABASE || "hrms",
      port: Number(process.env.MYSQL_PORT) || 3306,

      waitForConnections: true,
      connectionLimit: 5,
      queueLimit: 0,

      connectTimeout: 10000,
      enableKeepAlive: true,
      keepAliveInitialDelay: 0,
    };

    // Only enable SSL if explicitly requested or connecting to a remote host with SSL enabled
    if (process.env.MYSQL_SSL === "true") {
      dbConfig.ssl = { rejectUnauthorized: false };
    }

    db = mysql.createPool(dbConfig);

    // Test connection pool
    const connection = await db.getConnection();
    console.log(" Connected to MySQL DB successfully");
    connection.release();

    await createTables(db);
    console.log(" Tables created successfully");
  } catch (err) {
    console.error(" DB Connection Error:", err.message);

    if (err.code === "ECONNREFUSED") {
      console.error("\n Help: Could not connect to MySQL server.");
      console.error("1. Make sure MySQL service is running on your machine.");
      console.error("2. Check host and port settings in your backend .env file.\n");
    }

    process.exit(1);
  }
};

const getDB = () => db;

module.exports = { initializeDB, getDB };
