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
  const { full_name, phone, email, accompanist_type, student_id, assigned_events } = body;

  if (!full_name || !phone || !accompanist_type || !assigned_events) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'full_name, phone, accompanist_type, and assigned_events are required' }),
    };
  }

  // Check quota
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
      body: JSON.stringify({ error: 'College quota exceeded (45/45). Remove existing participants before adding new ones.' }),
    };
  }

  // Get college_code
  const collegeResult = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT college_code
      FROM colleges
      WHERE college_id = @college_id
    `);

  if (collegeResult.recordset.length === 0) {
    return {
      statusCode: 404,
      headers,
      body: JSON.stringify({ error: 'College not found' }),
    };
  }

  const college_code = collegeResult.recordset[0].college_code;

  // Generate session_id
  const session_id = crypto.randomBytes(32).toString('hex');
  const expires_at = new Date(Date.now() + 25 * 60 * 1000);

  // Store session
  await pool
    .request()
    .input('session_id', sql.VarChar(64), session_id)
    .input('college_id', sql.Int, auth.college_id)
    .input('full_name', sql.VarChar(255), full_name)
    .input('phone', sql.VarChar(20), phone)
    .input('email', sql.VarChar(255), email || null)
    .input('accompanist_type', sql.VarChar(20), accompanist_type)
    .input('student_id', sql.Int, student_id || null)
    .input('assigned_events', sql.VarChar(500), JSON.stringify(assigned_events))
    .input('expires_at', sql.DateTime2, expires_at)
    .query(`
      INSERT INTO accompanist_sessions (
        session_id, college_id, full_name, phone, email, accompanist_type, student_id, assigned_events, expires_at
      )
      VALUES (@session_id, @college_id, @full_name, @phone, @email, @accompanist_type, @student_id, @assigned_events, @expires_at)
    `);

  // Generate SAS URLs
  const blobBasePath = `${college_code}/accompanist-details/${full_name}_${phone}`;
  const upload_urls = {
    passport_photo: generateSASUrl(`${blobBasePath}/passport_photo`),
    id_proof: generateSASUrl(`${blobBasePath}/id_proof`),
  };

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      success: true,
      session_id,
      upload_urls,
      expires_at: expires_at.toISOString(),
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
      body: JSON.stringify({ error: 'session_id is required' }),
    };
  }

  // Validate session
  const sessionResult = await pool
    .request()
    .input('session_id', sql.VarChar(64), session_id)
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT 
        full_name, phone, email, accompanist_type, student_id, assigned_events, expires_at
      FROM accompanist_sessions
      WHERE session_id = @session_id AND college_id = @college_id
    `);

  if (sessionResult.recordset.length === 0) {
    return {
      statusCode: 404,
      headers,
      body: JSON.stringify({ error: 'Invalid or expired session' }),
    };
  }

  const session = sessionResult.recordset[0];
  const expires_at = new Date(session.expires_at);

  if (Date.now() > expires_at.getTime()) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Session expired. Please restart.' }),
    };
  }

  // Get college_code
  const collegeResult = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT college_code
      FROM colleges
      WHERE college_id = @college_id
    `);

  const college_code = collegeResult.recordset[0].college_code;

  // Insert accompanist
  const insertResult = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .input('full_name', sql.VarChar(255), session.full_name)
    .input('phone', sql.VarChar(20), session.phone)
    .input('email', sql.VarChar(255), session.email)
    .input('accompanist_type', sql.VarChar(20), session.accompanist_type)
    .input('student_id', sql.Int, session.student_id)
    .input('passport_photo_url', sql.VarChar(500), `https://${AZURE_STORAGE_ACCOUNT_NAME}.blob.core.windows.net/${CONTAINER_NAME}/${college_code}/accompanist-details/${session.full_name}_${session.phone}/passport_photo`)
    .input('id_proof_url', sql.VarChar(500), `https://${AZURE_STORAGE_ACCOUNT_NAME}.blob.core.windows.net/${CONTAINER_NAME}/${college_code}/accompanist-details/${session.full_name}_${session.phone}/id_proof`)
    .query(`
      INSERT INTO accompanists (
        college_id, full_name, phone, email, accompanist_type, student_id, passport_photo_url, id_proof_url
      )
      OUTPUT INSERTED.accompanist_id
      VALUES (@college_id, @full_name, @phone, @email, @accompanist_type, @student_id, @passport_photo_url, @id_proof_url)
    `);

  const accompanist_id = insertResult.recordset[0].accompanist_id;

  // Insert event assignments
  const assigned_events = JSON.parse(session.assigned_events);
  for (const event_id of assigned_events) {
    await pool
      .request()
      .input('accompanist_id', sql.Int, accompanist_id)
      .input('event_id', sql.Int, event_id)
      .input('college_id', sql.Int, auth.college_id)
      .input('assigned_by_user_id', sql.Int, auth.user_id)
      .query(`
        INSERT INTO accompanist_event_participation (
          accompanist_id, event_id, college_id, assigned_by_user_id
        )
        VALUES (@accompanist_id, @event_id, @college_id, @assigned_by_user_id)
      `);
  }

  // Delete session
  await pool
    .request()
    .input('session_id', sql.VarChar(64), session_id)
    .query(`DELETE FROM accompanist_sessions WHERE session_id = @session_id`);

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      success: true,
      message: 'Accompanist added successfully',
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
        accompanist_type
      FROM accompanists
      WHERE college_id = @college_id
      ORDER BY full_name ASC
    `);

  const accompanists = [];

  for (const acc of result.recordset) {
    const eventsResult = await pool
      .request()
      .input('accompanist_id', sql.Int, acc.accompanist_id)
      .query(`
        SELECT e.event_id, e.event_name
        FROM accompanist_event_participation aep
        INNER JOIN events e ON aep.event_id = e.event_id
        WHERE aep.accompanist_id = @accompanist_id
      `);

    accompanists.push({
      accompanist_id: acc.accompanist_id,
      full_name: acc.full_name,
      phone: acc.phone,
      email: acc.email,
      accompanist_type: acc.accompanist_type,
      assigned_events: eventsResult.recordset.map(e => ({
        event_id: e.event_id,
        event_name: e.event_name,
      })),
    });
  }

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

    if (action === 'init_accompanist') {
      return await initAccompanist(pool, auth, body);
    } else if (action === 'finalize_accompanist') {
      return await finalizeAccompanist(pool, auth, body);
    } else if (action === 'get_accompanists') {
      return await getAccompanists(pool, auth);
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