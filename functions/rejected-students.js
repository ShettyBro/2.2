const sql = require('mssql');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  options: {
    encrypt: true,
    trustServerCertificate: false,
  },
};

const JWT_SECRET = process.env.JWT_SECRET;

const headers = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

const verifyAuth = (event) => {
  const authHeader = event.headers.authorization || event.headers.Authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new Error('Missing or invalid Authorization header');
  }

  const token = authHeader.substring(7);
  const decoded = jwt.verify(token, JWT_SECRET);

  if (decoded.role !== 'PRINCIPAL' && decoded.role !== 'MANAGER') {
    throw new Error('Unauthorized: Principal or Manager role required');
  }

  return {
    user_id: decoded.user_id,
    role: decoded.role,
    college_id: decoded.college_id,
  };
};

// ============================================================================
// MAIN HANDLER
// ============================================================================
exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' }),
    };
  }

  let pool;
  try {
    const auth = verifyAuth(event);
    pool = await sql.connect(dbConfig);

    const result = await pool
      .request()
      .input('college_id', sql.Int, auth.college_id)
      .query(`
        SELECT 
          sa.student_id,
          s.full_name,
          s.usn,
          s.email,
          s.phone,
          sa.rejected_reason,
          sa.reviewed_at,
          s.reapply_count
        FROM student_applications sa
        INNER JOIN students s ON sa.student_id = s.student_id
        WHERE s.college_id = @college_id
          AND sa.status = 'REJECTED'
        ORDER BY sa.reviewed_at DESC
      `);

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        students: result.recordset,
      }),
    };
  } catch (error) {
    console.error('Error:', error);

    if (error.message.includes('Authorization') || error.message.includes('Unauthorized')) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: error.message }),
      };
    }

    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        error: 'Internal server error',
        details: error.message,
      }),
    };
  } finally {
    if (pool) {
      await pool.close();
    }
  }
};