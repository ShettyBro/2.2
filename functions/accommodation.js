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

  if (decoded.role !== 'principal' && decoded.role !== 'manager') {
    throw new Error('Unauthorized: Principal or Manager role required');
  }

  return {
    user_id: decoded.user_id,
    full_name: decoded.full_name,
    role: decoded.role,
    college_id: decoded.college_id,
  };
};

// ============================================================================
// ACTION: submit_accommodation
// ============================================================================
const submitAccommodation = async (pool, auth, body) => {
  const {
    total_boys,
    total_girls,
    contact_person_name,
    contact_person_phone,
    contact_email,
    special_requirements,
  } = body;

  if (!total_boys || !total_girls || !contact_person_name || !contact_person_phone || !contact_email) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'All required fields must be filled' }),
    };
  }

  // Check if accommodation already exists
  const existingResult = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT accommodation_id
      FROM accommodation_requests
      WHERE college_id = @college_id
    `);

  if (existingResult.recordset.length > 0) {
    return {
      statusCode: 403,
      headers,
      body: JSON.stringify({ error: 'Accommodation request already submitted for this college' }),
    };
  }

  // Insert accommodation request
  await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .input('total_boys', sql.Int, parseInt(total_boys))
    .input('total_girls', sql.Int, parseInt(total_girls))
    .input('contact_person_name', sql.VarChar(255), contact_person_name)
    .input('contact_person_phone', sql.VarChar(20), contact_person_phone)
    .input('contact_email', sql.VarChar(255), contact_email)
    .input('special_requirements', sql.VarChar(500), special_requirements || null)
    .input('applied_by_user_id', sql.Int, auth.user_id)
    .input('applied_by_type', sql.VarChar(20), auth.role)
    .query(`
      INSERT INTO accommodation_requests (
        college_id, total_boys, total_girls, contact_person_name, contact_person_phone, 
        contact_email, special_requirements, applied_by_user_id, applied_by_type, status
      )
      VALUES (
        @college_id, @total_boys, @total_girls, @contact_person_name, @contact_person_phone,
        @contact_email, @special_requirements, @applied_by_user_id, @applied_by_type, 'PENDING'
      )
    `);

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      success: true,
      message: 'Accommodation request submitted successfully',
    }),
  };
};

// ============================================================================
// ACTION: get_accommodation_status
// ============================================================================
const getAccommodationStatus = async (pool, auth) => {
  const result = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT 
        total_boys,
        total_girls,
        contact_person_name,
        contact_person_phone,
        contact_email,
        special_requirements,
        status,
        applied_at,
        admin_remarks
      FROM accommodation_requests
      WHERE college_id = @college_id
    `);

  if (result.recordset.length === 0) {
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        accommodation: null,
      }),
    };
  }

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      success: true,
      accommodation: result.recordset[0],
    }),
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

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Invalid JSON body' }),
    };
  }

  const { action } = body;

  if (!action) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'action is required' }),
    };
  }

  let pool;
  try {
    const auth = verifyAuth(event);
    pool = await sql.connect(dbConfig);

    if (action === 'submit_accommodation') {
      return await submitAccommodation(pool, auth, body);
    } else if (action === 'get_accommodation_status') {
      return await getAccommodationStatus(pool, auth);
    } else {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Invalid action' }),
      };
    }
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