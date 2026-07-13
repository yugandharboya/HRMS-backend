const mysql = require("mysql2/promise");
const createTables = require("./createTables");

let db = null;

const initializeDB = async () => {
  try {
    db = mysql.createPool({
      host: process.env.MYSQL_HOST,
      user: process.env.MYSQL_USER,
      password: process.env.MYSQL_PASSWORD,
      database: process.env.MYSQL_DATABASE,
      port: process.env.MYSQL_PORT,

      waitForConnections: true,
      connectionLimit: 5,
      queueLimit: 0,

      connectTimeout: 10000,
      enableKeepAlive: true,
      keepAliveInitialDelay: 0,

      ssl: {
        rejectUnauthorized: false,
      },
    });

    console.log("Connected to MySQL DB");

    await createTables(db);
    console.log("Tables created successfully");
  } catch (err) {
    console.error("DB Connection Error:  ", err);
    process.exit(1);
  }
};

const getDB = () => db;

module.exports = { initializeDB, getDB };
