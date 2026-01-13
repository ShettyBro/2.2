const sql = require('mssql');

const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  options: {
    encrypt: true,               // REQUIRED for Azure SQL
    trustServerCertificate: false
  },
  pool: {
    max: 5,
    min: 0,
    idleTimeoutMillis: 30000
  }
};

let pool;

/**
 * Reuse connection across invocations (important for serverless)
 */
async function getPool() {
  if (pool) return pool;
  pool = await sql.connect(dbConfig);
  return pool;
}

module.exports = {
  sql,
  getPool
};
