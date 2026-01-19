const sql = require('mssql');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { BlobServiceClient, generateBlobSASQueryParameters, BlobSASPermissions, StorageSharedKeyCredential } = require('@azure/storage-blob');
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
const AZURE_STORAGE_ACCOUNT_NAME = process.env.AZURE_STORAGE_ACCOUNT_NAME;
const AZURE_STORAGE_ACCOUNT_KEY = process.env.AZURE_STORAGE_ACCOUNT_KEY;
const CONTAINER_NAME = 'student-documents';

const headers = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

const verifyAuth = (event) => {
  try {
    const authHeader = event.headers.authorization || event.headers.Authorization;
    
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({
          success: false,
          message: "Token expired. Redirecting to login...",
          redirect: "https://vtufest2026.acharyahabba.com/",
        }),
      };
    }

    const token = authHeader.substring(7);
    let decoded;

    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({
          success: false,
          message: "Token expired. Redirecting to login...",
          redirect: "https://vtufest2026.acharyahabba.com/",
        }),
      };
    }

    if (decoded.role !== 'PRINCIPAL' && decoded.role !== 'MANAGER') {
      throw new Error('Unauthorized: Principal or Manager role required');
    }

    const auth = {
      user_id: decoded.user_id,
      college_id: decoded.college_id,
      role: decoded.role,
    };
    return auth;
  } catch (error) {
    throw error;
  }
};

const generateSASUrl = (blobPath) => {
  const sharedKeyCredential = new StorageSharedKeyCredential(
    AZURE_STORAGE_ACCOUNT_NAME,
    AZURE_STORAGE_ACCOUNT_KEY
  );

  const blobServiceClient = new BlobServiceClient(
    `https://${AZURE_STORAGE_ACCOUNT_NAME}.blob.core.windows.net`,
    sharedKeyCredential
  );

  const containerClient = blobServiceClient.getContainerClient(CONTAINER_NAME);
  const blobClient = containerClient.getBlobClient(blobPath);

  const expiresOn = new Date(Date.now() + 25 * 60 * 1000);

  const sasToken = generateBlobSASQueryParameters(
    {
      containerName: CONTAINER_NAME,
      blobName: blobPath,
      permissions: BlobSASPermissions.parse('w'),
      expiresOn,
    },
    sharedKeyCredential
  ).toString();

  return `${blobClient.url}?${sasToken}`;
};

// ============================================================================
// ACTION: init_accompanist
// ============================================================================
const initAccompanist = async (pool, auth, body) => {
  const { full_name, phone, email, accompanist_type, student_id } = body;

  // Validate required fields
  if (!full_name || !phone || !accompanist_type) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ success: false, error: 'full_name, phone, and accompanist_type are required' }),
    };
  }

  // Validate accompanist_type (ONLY faculty or professional, NO student)
  if (!['faculty', 'professional'].includes(accompanist_type)) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ success: false, error: 'accompanist_type must be either "faculty" or "professional"' }),
    };
  }

  // Check overall quota (45 total: students + accompanists)
  const quotaCheck = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT 
        (SELECT COUNT(DISTINCT sa.student_id)
         FROM student_applications sa
         INNER JOIN students s ON sa.student_id = s.student_id
         WHERE s.college_id = @college_id AND sa.status = 'APPROVED') +
        (SELECT COUNT(*)
         FROM accompanists
         WHERE college_id = @college_id) AS quota_used
    `);

  const quota_used = quotaCheck.recordset[0].quota_used;

  if (quota_used >= 45) {
    return {
      statusCode: 403,
      headers,
      body: JSON.stringify({ 
        success: false,
        error: 'College quota exceeded (45/45). Remove existing participants before adding new ones.',
        quota_used: quota_used
      }),
    };
  }

  // Get college_code and college_name
  const collegeResult = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT college_code, college_name
      FROM colleges
      WHERE college_id = @college_id
    `);

  if (collegeResult.recordset.length === 0) {
    return {
      statusCode: 404,
      headers,
      body: JSON.stringify({ success: false, error: 'College not found' }),
    };
  }

  const college_code = collegeResult.recordset[0].college_code;
  const college_name = collegeResult.recordset[0].college_name;

  // Generate session_id
  const session_id = crypto.randomBytes(32).toString('hex');
  const expires_at = new Date(Date.now() + 25 * 60 * 1000);

  // Store session (WITHOUT assigned_events column)
  await pool
    .request()
    .input('session_id', sql.VarChar(64), session_id)
    .input('college_id', sql.Int, auth.college_id)
    .input('full_name', sql.VarChar(255), full_name)
    .input('phone', sql.VarChar(20), phone)
    .input('email', sql.VarChar(255), email || null)
    .input('accompanist_type', sql.VarChar(20), accompanist_type)
    .input('student_id', sql.Int, student_id || null)
    .input('expires_at', sql.DateTime2, expires_at)
    .query(`
      INSERT INTO accompanist_sessions (
        session_id, college_id, full_name, phone, email, accompanist_type, student_id, expires_at
      )
      VALUES (@session_id, @college_id, @full_name, @phone, @email, @accompanist_type, @student_id, @expires_at)
    `);

  // Generate SAS URLs for document uploads (renamed to match frontend)
  const blobBasePath = `${college_code}/accompanist-details/${full_name}_${phone}`;
  const upload_urls = {
    passport_photo: generateSASUrl(`${blobBasePath}/passport_photo`),
    government_id_proof: generateSASUrl(`${blobBasePath}/government_id_proof`),
  };

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      success: true,
      session_id,
      upload_urls,
      expires_at: expires_at.toISOString(),
      quota_remaining: 45 - quota_used - 1
    }),
  };
};

// ============================================================================
// ACTION: finalize_accompanist
// ============================================================================
const finalizeAccompanist = async (pool, auth, body) => {
  const { session_id } = body;

  if (!session_id) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ success: false, error: 'session_id is required' }),
    };
  }

  // Validate session
  const sessionResult = await pool
    .request()
    .input('session_id', sql.VarChar(64), session_id)
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT 
        full_name, phone, email, accompanist_type, student_id, expires_at
      FROM accompanist_sessions
      WHERE session_id = @session_id AND college_id = @college_id
    `);

  if (sessionResult.recordset.length === 0) {
    return {
      statusCode: 404,
      headers,
      body: JSON.stringify({ success: false, error: 'Invalid or expired session' }),
    };
  }

  const session = sessionResult.recordset[0];
  const expires_at = new Date(session.expires_at);

  if (Date.now() > expires_at.getTime()) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ success: false, error: 'Session expired. Please restart.' }),
    };
  }

  // Get college_code and college_name
  const collegeResult = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT college_code, college_name
      FROM colleges
      WHERE college_id = @college_id
    `);

  const college_code = collegeResult.recordset[0].college_code;
  const college_name = collegeResult.recordset[0].college_name;

  // Insert accompanist record ONLY (NO event assignment)
  const insertResult = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .input('college_name', sql.VarChar(255), college_name)
    .input('full_name', sql.VarChar(255), session.full_name)
    .input('phone', sql.VarChar(20), session.phone)
    .input('email', sql.VarChar(255), session.email)
    .input('accompanist_type', sql.VarChar(20), session.accompanist_type)
    .input('student_id', sql.Int, session.student_id)
    .input('passport_photo_url', sql.VarChar(500), `https://${AZURE_STORAGE_ACCOUNT_NAME}.blob.core.windows.net/${CONTAINER_NAME}/${college_code}/accompanist-details/${session.full_name}_${session.phone}/passport_photo`)
    .input('id_proof_url', sql.VarChar(500), `https://${AZURE_STORAGE_ACCOUNT_NAME}.blob.core.windows.net/${CONTAINER_NAME}/${college_code}/accompanist-details/${session.full_name}_${session.phone}/government_id_proof`)
    .query(`
      INSERT INTO accompanists (
        college_id,
        college_name,
        full_name,
        phone,
        email,
        accompanist_type,
        student_id,
        passport_photo_url,
        id_proof_url
      )
      OUTPUT INSERTED.accompanist_id
      VALUES (
        @college_id,
        @college_name,
        @full_name,
        @phone,
        @email,
        @accompanist_type,
        @student_id,
        @passport_photo_url,
        @id_proof_url
      )
    `);

  const accompanist_id = insertResult.recordset[0].accompanist_id;

  // Delete session after successful registration
  await pool
    .request()
    .input('session_id', sql.VarChar(64), session_id)
    .query(`DELETE FROM accompanist_sessions WHERE session_id = @session_id`);

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      success: true,
      message: 'Accompanist registered successfully. Event assignment can be done separately.',
      accompanist_id,
    }),
  };
};

// ============================================================================
// ACTION: get_accompanists
// ============================================================================
const getAccompanists = async (pool, auth) => {
  const result = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT 
        accompanist_id,
        full_name,
        phone,
        email,
        accompanist_type,
        student_id,
        created_at
      FROM accompanists
      WHERE college_id = @college_id
      ORDER BY created_at DESC
    `);

  // Map results WITHOUT fetching events (events table is deprecated)
  // Event assignment is handled separately in event_* tables
  const accompanists = result.recordset.map(acc => ({
    accompanist_id: acc.accompanist_id,
    full_name: acc.full_name,
    phone: acc.phone,
    email: acc.email,
    accompanist_type: acc.accompanist_type,
    student_id: acc.student_id,
    created_at: acc.created_at,
    assigned_events: [], // Empty array - events not managed here
  }));

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      success: true,
      accompanists,
    }),
  };
};

// ============================================================================
// ACTION: update_accompanist_details
// ============================================================================
const updateAccompanistDetails = async (pool, auth, body) => {
  const { accompanist_id, full_name, phone, email } = body;

  if (!accompanist_id) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ success: false, error: 'accompanist_id is required' }),
    };
  }

  if (!full_name || !phone) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ success: false, error: 'full_name and phone are required' }),
    };
  }

  // Verify accompanist belongs to this college
  const verifyResult = await pool
    .request()
    .input('accompanist_id', sql.Int, accompanist_id)
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT accompanist_id
      FROM accompanists
      WHERE accompanist_id = @accompanist_id AND college_id = @college_id
    `);

  if (verifyResult.recordset.length === 0) {
    return {
      statusCode: 404,
      headers,
      body: JSON.stringify({ success: false, error: 'Accompanist not found or does not belong to your college' }),
    };
  }

  // Update ONLY text fields (full_name, phone, email)
  await pool
    .request()
    .input('accompanist_id', sql.Int, accompanist_id)
    .input('full_name', sql.VarChar(255), full_name)
    .input('phone', sql.VarChar(20), phone)
    .input('email', sql.VarChar(255), email || null)
    .query(`
      UPDATE accompanists
      SET 
        full_name = @full_name,
        phone = @phone,
        email = @email
      WHERE accompanist_id = @accompanist_id
    `);

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      success: true,
      message: 'Accompanist details updated successfully',
    }),
  };
};

// ============================================================================
// ACTION: delete_accompanist
// ============================================================================
const deleteAccompanist = async (pool, auth, body) => {
  const { accompanist_id } = body;

  if (!accompanist_id) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ success: false, error: 'accompanist_id is required' }),
    };
  }

  // Verify accompanist belongs to this college
  const verifyResult = await pool
    .request()
    .input('accompanist_id', sql.Int, accompanist_id)
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT accompanist_id
      FROM accompanists
      WHERE accompanist_id = @accompanist_id AND college_id = @college_id
    `);

  if (verifyResult.recordset.length === 0) {
    return {
      statusCode: 404,
      headers,
      body: JSON.stringify({ success: false, error: 'Accompanist not found or does not belong to your college' }),
    };
  }

  // Delete accompanist (this will cascade delete from accompanist_event_participation if FK is set)
  await pool
    .request()
    .input('accompanist_id', sql.Int, accompanist_id)
    .query(`DELETE FROM accompanists WHERE accompanist_id = @accompanist_id`);

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      success: true,
      message: 'Accompanist removed successfully',
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
    
    // Handle 401 responses from verifyAuth
    if (auth.statusCode === 401) {
      return auth;
    }

    pool = await sql.connect(dbConfig);

    if (action === 'init_accompanist') {
      return await initAccompanist(pool, auth, body);
    } else if (action === 'finalize_accompanist') {
      return await finalizeAccompanist(pool, auth, body);
    } else if (action === 'get_accompanists') {
      return await getAccompanists(pool, auth);
    } else if (action === 'update_accompanist_details') {
      return await updateAccompanistDetails(pool, auth, body);
    } else if (action === 'delete_accompanist') {
      return await deleteAccompanist(pool, auth, body);
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