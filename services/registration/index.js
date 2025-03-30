const express = require('express');
const { Pool } = require('pg');
const fetch = require('node-fetch');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const cors = require('cors');

const CONSUL_HOST = process.env.CONSUL_HOST || 'consul';
const CONSUL_PORT = process.env.CONSUL_PORT || 8500;

const app = express();
app.use(express.json());
app.use(cors({ origin: true, credentials: true }));

// PostgreSQL connection pool
const pool = new Pool({
  user: process.env.POSTGRES_USER || 'admin',
  host: process.env.POSTGRES_HOST || 'postgres',
  database: process.env.POSTGRES_DB || 'registration',
  password: process.env.POSTGRES_PASSWORD || 'password',
  port: 5432,
});


// Authentication middleware
const client = jwksClient({
  jwksUri: process.env.KEYCLOAK_JWKS_URI || 'http://host.docker.internal:8080/realms/digit30/protocol/openid-connect/certs',
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    const signingKey = key?.publicKey || key?.rsaPublicKey;
    callback(err, signingKey);
  });
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: Missing or invalid Authorization header' });
  }
  const token = authHeader.split(' ')[1];
  jwt.verify(token, getKey, {
    issuer: process.env.KEYCLOAK_ISSUER || 'http://localhost:8080/realms/digit30',
    audience: process.env.KEYCLOAK_AUDIENCE || 'account',
  }, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid or expired token' });
    req.user = decoded;
    next();
  });
}

// Helper to discover and call registry service
async function registerToRegistry(serviceId, data, token) {
  const services = await consul.catalog.service.nodes('registry-service');
  if (!services.length) throw new Error('Registry service not found');
  
  const { Address, ServicePort } = services[0]; // Use first available instance
  const url = `http://${Address}:${ServicePort}/data/${serviceId}/1/createEntries`;
  
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      'Information-Mediator-Client': 'eGovStack/GOV/90000009/registration'
    },
    body: JSON.stringify({ write: [{ content: data }] })
  });
  if (!response.ok) throw new Error(`Registry service error: ${response.status}`);
  return await response.json();
}

// Initialize database tables
async function initializeTables() {
  const tables = [
    `CREATE TABLE IF NOT EXISTS services (
      id UUID PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      version VARCHAR(50),
      description TEXT,
      is_executable BOOLEAN DEFAULT true,
      is_closed BOOLEAN DEFAULT false,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE TABLE IF NOT EXISTS eforms (
      id UUID PRIMARY KEY,
      service_id UUID REFERENCES services(id),
      name VARCHAR(255) NOT NULL,
      description TEXT,
      version VARCHAR(50),
      schema JSONB,
      latest BOOLEAN DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE TABLE IF NOT EXISTS applications (
      file_id UUID PRIMARY KEY,
      service_id UUID REFERENCES services(id),
      applicant_id VARCHAR(255),
      application_name VARCHAR(255),
      status VARCHAR(50) DEFAULT 'PENDING',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      registered_at TIMESTAMPTZ,
      form_data JSONB,
      document_urls TEXT[],
      ended BOOLEAN DEFAULT false
    )`,
    `CREATE TABLE IF NOT EXISTS tasks (
      task_id UUID PRIMARY KEY,
      file_id UUID REFERENCES applications(file_id),
      role_id UUID,
      assignee_id VARCHAR(255),
      task_name VARCHAR(255),
      status VARCHAR(50) DEFAULT 'PENDING',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      form_variables JSONB
    )`
  ];

  for (const query of tables) {
    await pool.query(query);
  }
}

// Register service with Consul
async function registerServiceWithConsul({ ID, Name, Address, Port }) {
    const maxRetries = 5;
    let attempt = 0;
  
    while (attempt < maxRetries) {
      try {
        const response = await fetch(`http://${CONSUL_HOST}:${CONSUL_PORT}/v1/agent/service/register`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            ID,
            Name,
            Address,
            Port
          })
        });
        if (!response.ok) {
          throw new Error(`Consul registration failed: ${response.status} ${await response.text()}`);
        }
        console.log(`Registered with Consul as ${ID} on port ${Port}`);
        return;
      } catch (err) {
        console.error(`Attempt ${attempt + 1} failed to register with Consul: ${err.message}`);
        attempt++;
        if (attempt === maxRetries) {
          console.error(`Failed to register with Consul after ${maxRetries} attempts: ${err.message}`);
        }
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }
  }
  
  async function deregisterServiceFromConsul(serviceId) {
    try {
      const response = await fetch(`http://${CONSUL_HOST}:${CONSUL_PORT}/v1/agent/service/deregister/${serviceId}`, {
        method: 'PUT'
      });
      if (!response.ok) {
        throw new Error(`Consul deregistration failed: ${response.status} ${await response.text()}`);
      }
      console.log(`Deregistered ${serviceId} from Consul`);
    } catch (err) {
      console.error(`Failed to deregister ${serviceId} from Consul: ${err.message}`);
    }
  }

async function registerService(port) {
    const serviceId = `registration-${Date.now()}`; 
    const maxRetries = 5;
    let attempt = 0;
  
    while (attempt < maxRetries) {
      try {
        await registerServiceWithConsul({
          ID: serviceId,
          Name: 'registration-service', 
          Address: process.env.HOSTNAME || 'registration-service',
          Port: port
        });
        console.log(`Registered with Consul as ${serviceId} on port ${port}`);
  
        process.on('SIGINT', async () => {
          await deregisterServiceFromConsul(serviceId);
          console.log(`Deregistered ${serviceId} from Consul`);
          process.exit();
        });
        return;
      } catch (err) {
        console.error(`Attempt ${attempt + 1} failed to register with Consul: ${err.message}`);
        attempt++;
        if (attempt === maxRetries) {
          throw new Error(`Failed to register with Consul after ${maxRetries} attempts: ${err.message}`);
        }
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }
  }

// Health check endpoint
app.get('/health', (req, res) => res.status(200).json({ status: 'healthy' }));

// 8.1 Online Registration e-services
app.get('/services', authenticateToken, async (req, res) => {
  try {
    const { name } = req.query;
    let query = 'SELECT * FROM services';
    const values = [];
    
    if (name) {
      query += ' WHERE name ILIKE $1';
      values.push(`%${name}%`);
    }
    
    const result = await pool.query(query, values);
    const services = result.rows.map(row => ({
      id: row.id,
      name: row.name,
      version: row.version,
      type: 'None',
      isExecutable: row.is_executable,
      isClosed: row.is_closed,
      description: row.description,
      serviceBody: []
    }));
    res.status(200).json(services);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/services/:serviceId', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM services WHERE id = $1', [req.params.serviceId]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Service not found' });
    const row = result.rows[0];
    res.status(200).json({
      id: row.id,
      name: row.name,
      version: row.version,
      type: 'None',
      isExecutable: row.is_executable,
      isClosed: row.is_closed,
      description: row.description,
      serviceBody: []
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/services/:serviceId/eForms', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM eforms WHERE service_id = $1', [req.params.serviceId]);
    const eForms = result.rows.map(row => ({
      eFormId: row.id,
      name: row.name,
      description: row.description,
      version: row.version,
      latest: row.latest
    }));
    res.status(200).json(eForms);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/eForms/:eFormId', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM eforms WHERE id = $1', [req.params.eFormId]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Not Found' });
    const row = result.rows[0];
    res.status(200).json({
      eFormId: row.id,
      name: row.name,
      description: row.description,
      version: row.version,
      latest: row.latest,
      schema: row.schema
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/services/:serviceId/applications', authenticateToken, async (req, res) => {
  const { serviceId } = req.params;
  const { applicationName, applicantId, created, formData, documentUrls } = req.body;
  const token = req.headers['authorization'].split(' ')[1];

  try {
    const serviceCheck = await pool.query('SELECT * FROM services WHERE id = $1', [serviceId]);
    if (serviceCheck.rows.length === 0) return res.status(404).json({ error: 'Service not found' });

    const fileId = uuidv4();
    const registeredAt = new Date().toISOString();
    
    const result = await pool.query(
      `INSERT INTO applications (file_id, service_id, applicant_id, application_name, registered_at, form_data, document_urls)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [fileId, serviceId, applicantId, applicationName, registeredAt, formData, documentUrls]
    );

    const application = result.rows[0];
    res.status(200).json({
      fileId: application.file_id,
      registered: application.registered_at,
      serviceId: application.service_id,
      serviceName: serviceCheck.rows[0].name,
      status: { code: application.status, title: application.status },
      ended: application.ended,
      applicationData: {
        applicationName: application.application_name,
        applicantId: application.applicant_id,
        created: application.created_at,
        formData: application.form_data,
        documentUrls: application.document_urls
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/documents', authenticateToken, async (req, res) => {
  try {
    const { file } = req.body;
    if (!file) return res.status(400).json({ error: 'File required' });
    const documentId = uuidv4();
    res.status(200).json({
      code: 1,
      type: 'document',
      message: 'File successfully uploaded',
      url: `/documents/${documentId}`
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 8.2 Processing of Registrations
app.get('/applications', authenticateToken, async (req, res) => {
  const { serviceId, applicantId, firstResult = 0, maxResult = 10, sortBy, sortOrder } = req.query;
  
  try {
    let query = 'SELECT a.*, s.name as service_name FROM applications a JOIN services s ON a.service_id = s.id';
    const conditions = [];
    const values = [];
    
    if (serviceId) {
      conditions.push('a.service_id = $' + (values.length + 1));
      values.push(serviceId);
    }
    if (applicantId) {
      conditions.push('a.applicant_id = $' + (values.length + 1));
      values.push(applicantId);
    }
    
    if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');
    if (sortBy) query += ` ORDER BY a.${sortBy} ${sortOrder || 'ASC'}`;
    query += ` LIMIT $${values.length + 1} OFFSET $${values.length + 2}`;
    values.push(maxResult, firstResult);

    const result = await pool.query(query, values);
    const applications = result.rows.map(row => ({
      fileId: row.file_id,
      registered: row.registered_at,
      serviceId: row.service_id,
      serviceName: row.service_name,
      status: { code: row.status, title: row.status },
      ended: row.ended,
      applicationData: {
        applicationName: row.application_name,
        applicantId: row.applicant_id,
        created: row.created_at,
        formData: row.form_data,
        documentUrls: row.document_urls
      }
    }));
    
    res.status(200).json(applications);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/applications/:fileId', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT a.*, s.name as service_name FROM applications a JOIN services s ON a.service_id = s.id WHERE a.file_id = $1',
      [req.params.fileId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Application file not found' });
    const row = result.rows[0];
    res.status(200).json({
      fileId: row.file_id,
      registered: row.registered_at,
      serviceId: row.service_id,
      serviceName: row.service_name,
      status: { code: row.status, title: row.status },
      ended: row.ended,
      applicationData: {
        applicationName: row.application_name,
        applicantId: row.applicant_id,
        created: row.created_at,
        formData: row.form_data,
        documentUrls: row.document_urls
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/applications/:fileId', authenticateToken, async (req, res) => {
  const { applicationName, applicantId, created, formData, documentUrls } = req.body;
  
  try {
    const result = await pool.query(
      `UPDATE applications SET 
        application_name = $1,
        applicant_id = $2,
        created_at = $3,
        form_data = $4,
        document_urls = $5,
        registered_at = NOW()
      WHERE file_id = $6 RETURNING *`,
      [applicationName, applicantId, created, formData, documentUrls, req.params.fileId]
    );
    
    if (result.rows.length === 0) return res.status(404).json({ error: 'Application file not found' });
    
    const row = result.rows[0];
    const service = await pool.query('SELECT name FROM services WHERE id = $1', [row.service_id]);
    
    res.status(200).json({
      fileId: row.file_id,
      registered: row.registered_at,
      serviceId: row.service_id,
      serviceName: service.rows[0].name,
      status: { code: row.status, title: row.status },
      ended: row.ended,
      applicationData: {
        applicationName: row.application_name,
        applicantId: row.applicant_id,
        created: row.created_at,
        formData: row.form_data,
        documentUrls: row.document_urls
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/tasks', authenticateToken, async (req, res) => {
  const { mainTaskId, fileId, assigneeId, firstResult = 0, maxResult = 10, sortBy, sortOrder } = req.query;
  
  try {
    let query = 'SELECT t.*, s.name as service_name FROM tasks t JOIN applications a ON t.file_id = a.file_id JOIN services s ON a.service_id = s.id';
    const conditions = [];
    const values = [];
    
    if (mainTaskId) {
      conditions.push('t.main_task_id = $' + (values.length + 1));
      values.push(mainTaskId);
    }
    if (fileId) {
      conditions.push('t.file_id = $' + (values.length + 1));
      values.push(fileId);
    }
    if (assigneeId) {
      conditions.push('t.assignee_id = $' + (values.length + 1));
      values.push(assigneeId);
    }
    
    if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');
    if (sortBy) query += ` ORDER BY t.${sortBy} ${sortOrder || 'ASC'}`;
    query += ` LIMIT $${values.length + 1} OFFSET $${values.length + 2}`;
    values.push(maxResult, firstResult);

    const result = await pool.query(query, values);
    const tasks = result.rows.map(row => ({
      taskId: row.task_id,
      mainTaskId: row.main_task_id,
      name: row.task_name,
      assigneeId: row.assignee_id,
      roleId: row.role_id,
      created: row.created_at,
      description: row.description,
      serviceId: row.service_id,
      serviceName: row.service_name,
      fileId: row.file_id,
      eFormId: row.eform_id,
      status: { code: row.status, title: row.status }
    }));
    
    res.status(200).json(tasks);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/tasks/:taskId', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT t.*, s.name as service_name FROM tasks t JOIN applications a ON t.file_id = a.file_id JOIN services s ON a.service_id = s.id WHERE t.task_id = $1',
      [req.params.taskId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Task not found' });
    const row = result.rows[0];
    res.status(200).json({
      taskId: row.task_id,
      taskName: row.task_name,
      assigneeId: row.assignee_id,
      roleId: row.role_id,
      created: row.created_at,
      description: row.description,
      fileId: row.file_id,
      serviceId: row.service_id,
      serviceName: row.service_name,
      eFormId: row.eform_id,
      formVariables: row.form_variables,
      status: { code: row.status, title: row.status }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/tasks/:taskId/complete', authenticateToken, async (req, res) => {
  const { data } = req.body;
  const token = req.headers['authorization'].split(' ')[1];
  
  try {
    const taskResult = await pool.query(
      'UPDATE tasks SET status = $1, form_variables = $2 WHERE task_id = $3 RETURNING *',
      ['COMPLETED', data, req.params.taskId]
    );
    
    if (taskResult.rows.length === 0) return res.status(404).json({ error: 'Task not found' });
    
    const task = taskResult.rows[0];
    const appResult = await pool.query('SELECT * FROM applications WHERE file_id = $1', [task.file_id]);
    
    const application = appResult.rows[0];
    await registerToRegistry(application.service_id, application.form_data, token);
    
    res.status(200).json({
      taskId: task.task_id,
      fileId: task.file_id,
      serviceId: application.service_id,
      status: { code: task.status, title: task.status },
      variables: { data }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Statistics endpoint
app.get('/data/statistics', authenticateToken, async (req, res) => {
  const { startDate, endDate, registrationName, operator, role, timeframe } = req.query;
  
  try {
    let query = 'SELECT COUNT(*) as count FROM applications a JOIN services s ON a.service_id = s.id';
    const conditions = [];
    const values = [];
    
    if (startDate) {
      conditions.push('a.created_at >= $' + (values.length + 1));
      values.push(startDate);
    }
    if (endDate) {
      conditions.push('a.created_at <= $' + (values.length + 1));
      values.push(endDate);
    }
    if (registrationName) {
      conditions.push('s.name ILIKE $' + (values.length + 1));
      values.push(`%${registrationName}%`);
    }
    
    if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');
    const result = await pool.query(query, values);
    res.status(200).json([{ count: result.rows[0].count }]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

async function startServer() {
    try {
      const server = app.listen(0, async () => {
        const port = server.address().port; // Corrected to use server object
        await registerService(port);
        console.log(`Registration Service running on dynamically assigned port ${port}`);
      });
    } catch (err) {
      console.error('Failed to start server:', err);
      process.exit(1);
    }
  }
  
startServer();