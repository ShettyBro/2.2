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
       const role = decoded.role;
 
 
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
// ACTION: get_payment_info
// ============================================================================
const getPaymentInfo = async (pool, auth) => {
  // Check if final approval is done
  const collegeResult = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT 
        college_code,
        college_name,
        is_final_approved
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

  const college = collegeResult.recordset[0];

  if (college.is_final_approved === 0) {
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        can_upload: false,
        message: 'Final approval not done yet. Payment is locked.',
      }),
    };
  }

  // Count total unique events college is participating in
  const eventsResult = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT DISTINCT e.event_id, e.event_name
      FROM student_event_participation sep
      INNER JOIN events e ON sep.event_id = e.event_id
      INNER JOIN students s ON sep.student_id = s.student_id
      WHERE s.college_id = @college_id
      
      UNION
      
      SELECT DISTINCT e.event_id, e.event_name
      FROM accompanist_event_participation aep
      INNER JOIN events e ON aep.event_id = e.event_id
      WHERE aep.college_id = @college_id
    `);

  const total_events = eventsResult.recordset.length;
  const events_list = eventsResult.recordset.map(e => e.event_name);

  // Calculate fee
  const amount_to_pay = total_events < 10 ? 8000 : 25000;

  // Check existing payment status
  const paymentResult = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT 
        status,
        uploaded_at,
        admin_remarks,
        receipt_url
      FROM payment_receipts
      WHERE college_id = @college_id
    `);

  let payment_status = null;
  if (paymentResult.recordset.length > 0) {
    const pay = paymentResult.recordset[0];
    payment_status = {
      status: pay.status,
      uploaded_at: pay.uploaded_at,
      admin_remarks: pay.admin_remarks,
      receipt_url: pay.receipt_url,
    };
  }

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      success: true,
      can_upload: true,
      total_events,
      events_list,
      amount_to_pay,
      payment_status,
    }),
  };
};

// ============================================================================
// ACTION: init_payment_upload
// ============================================================================
const initPaymentUpload = async (pool, auth, body) => {
  const { amount_paid } = body;

  if (!amount_paid) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'amount_paid is required' }),
    };
  }

  // Check if final approval is done
  const collegeResult = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT 
        college_code,
        college_name,
        is_final_approved
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

  const college = collegeResult.recordset[0];

  if (college.is_final_approved === 0) {
    return {
      statusCode: 403,
      headers,
      body: JSON.stringify({ error: 'Final approval not done yet. Cannot upload payment.' }),
    };
  }

  // Check if payment already exists
  const existingResult = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT receipt_id
      FROM payment_receipts
      WHERE college_id = @college_id
    `);

  if (existingResult.recordset.length > 0) {
    return {
      statusCode: 403,
      headers,
      body: JSON.stringify({ error: 'Payment receipt already uploaded for this college' }),
    };
  }

  // Generate session_id
  const session_id = crypto.randomBytes(32).toString('hex');
  const expires_at = new Date(Date.now() + 25 * 60 * 1000);

  // Store session
  await pool
    .request()
    .input('session_id', sql.VarChar(64), session_id)
    .input('college_id', sql.Int, auth.college_id)
    .input('amount_paid', sql.Int, parseInt(amount_paid))
    .input('expires_at', sql.DateTime2, expires_at)
    .query(`
      INSERT INTO payment_sessions (session_id, college_id, amount_paid, expires_at)
      VALUES (@session_id, @college_id, @amount_paid, @expires_at)
    `);

  // Generate SAS URL
  const blobPath = `${college.college_code}/payment-proofs/payment_proof`;
  const upload_url = generateSASUrl(blobPath);

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      success: true,
      session_id,
      upload_url,
      expires_at: expires_at.toISOString(),
    }),
  };
};

// ============================================================================
// ACTION: finalize_payment
// ============================================================================
const finalizePayment = async (pool, auth, body) => {
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
      SELECT amount_paid, expires_at
      FROM payment_sessions
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

  // Get college info
  const collegeResult = await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .query(`
      SELECT college_code, college_name
      FROM colleges
      WHERE college_id = @college_id
    `);

  const college = collegeResult.recordset[0];

  // Insert payment receipt
  await pool
    .request()
    .input('college_id', sql.Int, auth.college_id)
    .input('college_code', sql.VarChar(20), college.college_code)
    .input('college_name', sql.VarChar(255), college.college_name)
    .input('receipt_url', sql.VarChar(500), `https://${AZURE_STORAGE_ACCOUNT_NAME}.blob.core.windows.net/${CONTAINER_NAME}/${college.college_code}/payment-proofs/payment_proof`)
    .input('amount_paid', sql.Int, session.amount_paid)
    .input('uploaded_by_name', sql.VarChar(255), auth.full_name)
    .input('uploaded_by_type', sql.VarChar(20), auth.role)
    .query(`
      INSERT INTO payment_receipts (
        college_id, college_code, college_name, receipt_url, amount_paid, uploaded_by_name, uploaded_by_type, status
      )
      VALUES (
        @college_id, @college_code, @college_name, @receipt_url, @amount_paid, @uploaded_by_name, @uploaded_by_type, 'waiting_for_verification'
      )
    `);

  // Delete session
  await pool
    .request()
    .input('session_id', sql.VarChar(64), session_id)
    .query(`DELETE FROM payment_sessions WHERE session_id = @session_id`);

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      success: true,
      message: 'Payment receipt uploaded successfully',
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

    if (action === 'get_payment_info') {
      return await getPaymentInfo(pool, auth);
    } else if (action === 'init_payment_upload') {
      return await initPaymentUpload(pool, auth, body);
    } else if (action === 'finalize_payment') {
      return await finalizePayment(pool, auth, body);
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