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
app.use(cors({
  origin: true,
  credentials: true
}));

// PostgreSQL connection pool
const pool = new Pool({
  user: process.env.POSTGRES_USER || 'admin',
  host: process.env.POSTGRES_HOST || 'postgres',
  database: process.env.POSTGRES_DB || 'registry',
  password: process.env.POSTGRES_PASSWORD || 'password',
  port: 5432,
});


// JWKS client for token validation
const client = jwksClient({
  jwksUri: process.env.KEYCLOAK_JWKS_URI || 'http://host.docker.internal:8080/realms/digit30/protocol/openid-connect/certs',
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    const signingKey = key?.publicKey || key?.rsaPublicKey;
    callback(err, signingKey);
  });
}

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.log('Missing or invalid Authorization header');
    return res.status(401).json({ error: 'Unauthorized: Missing or invalid Authorization header' });
  }

  const token = authHeader.split(' ')[1];
  jwt.verify(token, getKey, {
    issuer: process.env.KEYCLOAK_ISSUER || 'http://localhost:8080/realms/digit30',
    audience: process.env.KEYCLOAK_AUDIENCE || 'account',
  }, (err, decoded) => {
    if (err) {
      console.error('Token verification failed:', err.message);
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    req.user = decoded;
    next();
  });
}

// Helper function to fetch schema from database-service
async function getDatabaseSchema(registryName, token) {
  try {
    const services = await consul.catalog.service.nodes('database-service');
    if (!services.length) throw new Error('Database service not found');
    const { Address, ServicePort } = services[0];
    const url = `http://${Address}:${ServicePort}/databases`;

    const response = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Information-Mediator-Client': 'eGovStack/GOV/90000009/digitalregistries',
      },
    });
    if (!response.ok) {
      console.error(`Failed to fetch databases: ${response.status} ${response.statusText}`);
      throw new Error(`Database service returned ${response.status}`);
    }
    const data = await response.json();
    console.log('Fetched databases:', JSON.stringify(data, null, 2));
    if (!data || !data.databases || !Array.isArray(data.databases)) {
      console.error('Invalid response format from database-service:', data);
      throw new Error('Invalid database response format');
    }
    const schema = data.databases.find(db => {
      if (!db || !db.code) {
        console.log('Skipping invalid database entry:', db);
        return false;
      }
      return db.code.toLowerCase() === registryName.toLowerCase();
    });
    if (!schema) {
      console.error(`Schema not found for registryName: ${registryName}`);
      throw new Error('Schema not found');
    }
    console.log('Found schema:', schema);
    return schema;
  } catch (err) {
    console.error('Error fetching database schema:', err.message);
    throw err;
  }
}

// Helper function to initialize registry table
async function initializeRegistryTable(registryName, schema) {
  const tableName = `registry_${registryName.toLowerCase()}`;
  let columns = [
    'uuid UUID UNIQUE',
    'created_at TIMESTAMPTZ DEFAULT NOW()',
    'modified_at TIMESTAMPTZ DEFAULT NOW()',
  ];

  for (const [key, value] of Object.entries(schema.properties)) {
    if (key === 'id') {
      columns.unshift(`"${key}" VARCHAR(255) PRIMARY KEY`);
    } else if (value.type === 'object') {
      columns.push(`"${key}" JSONB`);
    } else {
      let type = value.type === 'string' ? 'VARCHAR(255)' : 'INTEGER';
      columns.push(`"${key}" ${type}`);
    }
  }

  const createTableSQL = `CREATE TABLE IF NOT EXISTS ${tableName} (${columns.join(', ')});`;
  try {
    await pool.query(createTableSQL);
    console.log(`Initialized table: ${tableName}`);
  } catch (err) {
    console.error(`Error initializing table ${tableName}:`, err.message);
    throw err;
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
  const serviceId = `registry-${Date.now()}`; 
  const maxRetries = 5;
  let attempt = 0;

  while (attempt < maxRetries) {
    try {
      await registerServiceWithConsul({
        ID: serviceId,
        Name: 'registry-service',
        Address: process.env.HOSTNAME || 'registry-service',
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

// GET /data/{registryName}/{versionNumber}
app.post('/data/:registryName/:versionNumber/createEntries', authenticateToken, async (req, res) => {
  const { registryName, versionNumber } = req.params;
  const { write } = req.body;
  const token = req.headers['authorization'].split(' ')[1];

  if (!write || !Array.isArray(write)) {
    return res.status(400).json({ error: 'Missing or invalid write array' });
  }

  try {
    const schema = await getDatabaseSchema(registryName, token);
    if (!schema || schema.version !== versionNumber) {
      return res.status(404).json({ error: 'Registry or version not found' });
    }

    await initializeRegistryTable(registryName, schema.schema);

    const tableName = `registry_${registryName.toLowerCase()}`;
    const receive = [];

    for (const entry of write) {
      const content = { ...entry.content, uuid: uuidv4(), created_at: new Date().toISOString(), modified_at: new Date().toISOString() };
      const columns = Object.keys(content).map(key => `"${key}"`).join(', ');
      const placeholders = Object.keys(content).map((_, i) => `$${i + 1}`).join(', ');
      const values = Object.values(content);

      const result = await pool.query(`INSERT INTO ${tableName} (${columns}) VALUES (${placeholders}) RETURNING *`, values);
      receive.push({ content: result.rows[0] });
    }
    res.status(201).json({ receive });
  } catch (err) {
    console.error('Error in createEntries:', err);
    if (err.message === 'Registry or version not found') {
      return res.status(404).json({ error: 'Registry or version not found' });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /data/{registryName}/{versionNumber}/createEntries
app.post('/data/:registryName/:versionNumber/createEntries', authenticateToken, async (req, res) => {
  const { registryName, versionNumber } = req.params;
  const { write } = req.body;
  const token = req.headers['authorization'].split(' ')[1];

  if (!write || !Array.isArray(write)) {
    return res.status(400).json({ error: 'Missing or invalid write array' });
  }

  try {
    const schema = await getDatabaseSchema(registryName, token);
    if (!schema || schema.version !== versionNumber) {
      return res.status(404).json({ error: 'Registry or version not found' });
    }

    await initializeRegistryTable(registryName, schema.schema);

    const tableName = `registry_${registryName.toLowerCase()}`;
    const receive = [];

    for (const entry of write) {
      const content = { ...entry.content, uuid: uuidv4(), created_at: new Date().toISOString(), modified_at: new Date().toISOString() };
      const columns = Object.keys(content).map(key => `"${key}"`).join(', ');
      const placeholders = Object.keys(content).map((_, i) => `$${i + 1}`).join(', ');
      const values = Object.values(content);

      const result = await pool.query(`INSERT INTO ${tableName} (${columns}) VALUES (${placeholders}) RETURNING *`, values);
      receive.push({ content: result.rows[0] });
    }
    res.status(201).json({ receive });
  } catch (err) {
    console.error('Error in createEntries:', err);
    if (err.message === 'Registry or version not found') {
      return res.status(404).json({ error: 'Registry or version not found' });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /data/{registryName}/{versionNumber}/exists
app.post('/data/:registryName/:versionNumber/exists', authenticateToken, async (req, res) => {
  const { registryName, versionNumber } = req.params;
  const { query } = req.body;
  const token = req.headers['authorization'].split(' ')[1];

  if (!query || !query.content) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const schema = await getDatabaseSchema(registryName, token);
    if (!schema || schema.version !== versionNumber) {
      return res.status(404).json({ error: 'Registry or version not found' });
    }

    await initializeRegistryTable(registryName, schema.schema);

    const tableName = `registry_${registryName.toLowerCase()}`;
    const conditions = Object.entries(query.content).map(([key, value], i) => `"${key}" = $${i + 1}`).join(' AND ');
    const values = Object.values(query.content);

    const result = await pool.query(`SELECT EXISTS (SELECT 1 FROM ${tableName} WHERE ${conditions})`, values);
    res.status(200).json({ answer: { status: result.rows[0].exists, message: result.rows[0].exists ? 'Object found' : 'Object not found' } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /data/{registryName}/{versionNumber}/read
app.post('/data/:registryName/:versionNumber/read', authenticateToken, async (req, res) => {
  const { registryName, versionNumber } = req.params;
  const { query } = req.body;
  const token = req.headers['authorization'].split(' ')[1];

  if (!query || !query.content) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const schema = await getDatabaseSchema(registryName, token);
    if (!schema || schema.version !== versionNumber) {
      return res.status(404).json({ error: 'Registry or version not found' });
    }

    await initializeRegistryTable(registryName, schema.schema);

    const tableName = `registry_${registryName.toLowerCase()}`;
    const conditions = Object.entries(query.content).map(([key, value], i) => `"${key}" = $${i + 1}`).join(' AND ');
    const values = Object.values(query.content);

    const result = await pool.query(`SELECT * FROM ${tableName} WHERE ${conditions} LIMIT 1`, values);
    if (result.rows.length === 0) {
      return res.status(404).json({ detail: 'no record found' });
    }
    res.status(200).json({ content: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /data/{registryName}/{versionNumber}/update
app.put('/data/:registryName/:versionNumber/update', authenticateToken, async (req, res) => {
  const { registryName, versionNumber } = req.params;
  const { query, write } = req.body;
  const token = req.headers['authorization'].split(' ')[1];

  if (!query || !query.content || !write || !write.content) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const schema = await getDatabaseSchema(registryName, token);
    if (!schema || schema.version !== versionNumber) {
      return res.status(404).json({ error: 'Registry or version not found' });
    }

    await initializeRegistryTable(registryName, schema.schema);

    const tableName = `registry_${registryName.toLowerCase()}`;
    const queryConditions = Object.entries(query.content).map(([key, value], i) => `"${key}" = $${i + 1}`).join(' AND ');
    const queryValues = Object.values(query.content);
    const updateSet = Object.entries(write.content).map(([key, value], i) => `"${key}" = $${i + queryValues.length + 1}`).join(', ');
    const updateValues = [...queryValues, ...Object.values(write.content)];

    const result = await pool.query(`UPDATE ${tableName} SET ${updateSet}, modified_at = NOW() WHERE ${queryConditions} RETURNING *`, updateValues);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Record not found' });
    }
    res.status(200).json({ content: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /data/{registryName}/{versionNumber}/updateEntries
app.put('/data/:registryName/:versionNumber/updateEntries', authenticateToken, async (req, res) => {
  const { registryName, versionNumber } = req.params;
  const { query, write } = req.body;
  const token = req.headers['authorization'].split(' ')[1];

  if (!query || !query.content || !write || !write.content) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const schema = await getDatabaseSchema(registryName, token);
    if (!schema || schema.version !== versionNumber) {
      return res.status(404).json({ error: 'Registry or version not found' });
    }

    await initializeRegistryTable(registryName, schema.schema);

    const tableName = `registry_${registryName.toLowerCase()}`;
    const queryConditions = Object.entries(query.content).map(([key, value], i) => `"${key}" = $${i + 1}`).join(' AND ');
    const queryValues = Object.values(query.content);
    const updateSet = Object.entries(write.content).map(([key, value], i) => `"${key}" = $${i + queryValues.length + 1}`).join(', ');
    const updateValues = [...queryValues, ...Object.values(write.content)];

    const result = await pool.query(`UPDATE ${tableName} SET ${updateSet}, modified_at = NOW() WHERE ${queryConditions}`, updateValues);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'No records updated' });
    }
    res.status(200).json({ message: `${result.rowCount} records updated` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /data/{registryName}/{versionNumber}/updateOrCreate
app.post('/data/:registryName/:versionNumber/updateOrCreate', authenticateToken, async (req, res) => {
  const { registryName, versionNumber } = req.params;
  const { query, write } = req.body;
  const token = req.headers['authorization'].split(' ')[1];

  if (!query || !query.content || !write || !write.content) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const schema = await getDatabaseSchema(registryName, token);
    if (!schema || schema.version !== versionNumber) {
      return res.status(404).json({ error: 'Registry or version not found' });
    }

    await initializeRegistryTable(registryName, schema.schema);

    const tableName = `registry_${registryName.toLowerCase()}`;
    const queryConditions = Object.entries(query.content).map(([key, value], i) => `"${key}" = $${i + 1}`).join(' AND ');
    const queryValues = Object.values(query.content);
    const updateSet = Object.entries(write.content).map(([key, value], i) => `"${key}" = $${i + queryValues.length + 1}`).join(', ');
    const updateValues = [...queryValues, ...Object.values(write.content)];

    const updateResult = await pool.query(`UPDATE ${tableName} SET ${updateSet}, modified_at = NOW() WHERE ${queryConditions} RETURNING *`, updateValues);
    if (updateResult.rowCount > 0) {
      return res.status(200).json({ content: updateResult.rows[0] });
    }

    const content = { ...write.content, uuid: uuidv4(), created_at: new Date().toISOString(), modified_at: new Date().toISOString() };
    const columns = Object.keys(content).map(key => `"${key}"`).join(', ');
    const placeholders = Object.keys(content).map((_, i) => `$${i + 1}`).join(', ');
    const values = Object.values(content);

    const createResult = await pool.query(`INSERT INTO ${tableName} (${columns}) VALUES (${placeholders}) RETURNING *`, values);
    res.status(200).json({ content: createResult.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /data/{registryName}/{versionNumber}/{id}/delete
app.delete('/data/:registryName/:versionNumber/:id/delete', authenticateToken, async (req, res) => {
  const { registryName, versionNumber, id } = req.params;
  const token = req.headers['authorization'].split(' ')[1];

  try {
    const schema = await getDatabaseSchema(registryName, token);
    if (!schema || schema.version !== versionNumber) {
      return res.status(404).json({ error: 'Registry or version not found' });
    }

    await initializeRegistryTable(registryName, schema.schema);

    const tableName = `registry_${registryName.toLowerCase()}`;

    const result = await pool.query(`DELETE FROM ${tableName} WHERE id = $1`, [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Record not found' });
    }
    res.status(204).send();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /data/{registryName}/{versionNumber}/{uuid}/readValue/{field}.{ext}
app.get('/data/:registryName/:versionNumber/:uuid/readValue/:field.:ext', authenticateToken, async (req, res) => {
  const { registryName, versionNumber, uuid, field, ext } = req.params;
  const token = req.headers['authorization'].split(' ')[1];

  try {
    const schema = await getDatabaseSchema(registryName, token);
    if (!schema || schema.version !== versionNumber) {
      return res.status(404).json({ error: 'Registry or version not found' });
    }

    await initializeRegistryTable(registryName, schema.schema);

    const tableName = `registry_${registryName.toLowerCase()}`;

    const result = await pool.query(`SELECT "${field}" FROM ${tableName} WHERE uuid = $1`, [uuid]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Record not found' });
    }
    const value = result.rows[0][field];
    res.status(200).json({ value });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /data/mypersonalDataUsage
app.get('/data/mypersonalDataUsage', authenticateToken, async (req, res) => {
  const { userId, databaseId } = req.query;

  if (!userId || !databaseId) {
    return res.status(400).json({ error: 'Missing required parameters' });
  }

  // Placeholder for audit logs (not implemented in this schema)
  const mockLogs = [
    {
      id: '1',
      readerId: 'EE37819285773',
      readerInitials: 'JD',
      readerInstitutionId: 'EE70049837',
      readerInstitutionName: 'East Hospital',
      readerApplicationName: 'East Hospital healthcare back office',
      searchDateTime: '2017-07-21T17:32:28Z',
      refrences: [{ ReferenceId: 'MCTS31' }],
    },
  ];

  res.status(200).json(mockLogs);
});

// Initialize and start the server
async function startServer() {
  try {
    const server = app.listen(0, async () => {
      const port = server.address().port; // Corrected to use server object
      await registerService(port);
      console.log(`Digital Registries Service running on dynamically assigned port ${port}`);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

startServer();