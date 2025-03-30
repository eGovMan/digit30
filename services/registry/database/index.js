const express = require('express');
const { Pool } = require('pg');
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

// Authentication middleware using Identity Service tokens
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.log('Missing or invalid Authorization header');
    return res.status(401).json({ error: 'Unauthorized: Missing or invalid Authorization header' });
  }

  const token = authHeader.split(' ')[1];
  console.log('Received token:', token);

  jwt.verify(token, getKey, {
    issuer: process.env.KEYCLOAK_ISSUER || 'http://localhost:8080/realms/digit30',
    audience: process.env.KEYCLOAK_AUDIENCE || 'account',
  }, (err, decoded) => {
    if (err) {
      console.error('Token verification failed:', err.message);
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    console.log('Token decoded:', decoded);
    req.user = decoded;
    next();
  });
}

// Initialize database schema
async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS databases (
        id SERIAL PRIMARY KEY,
        group_name VARCHAR(255),
        catalog_name VARCHAR(255),
        code VARCHAR(50) UNIQUE,
        version VARCHAR(10) DEFAULT '1.0',
        name VARCHAR(255),
        description TEXT,
        institution VARCHAR(255),
        number_format VARCHAR(50),
        schema JSONB,
        schema_tags JSONB DEFAULT '[]',
        schema_flags JSONB DEFAULT '[]',
        fields_uniques JSONB DEFAULT '[]',
        is_draft BOOLEAN DEFAULT false,
        is_disabled BOOLEAN DEFAULT false,
        is_archived BOOLEAN DEFAULT false,
        modified_at TIMESTAMPTZ DEFAULT NOW(),
        by_user_name VARCHAR(255),
        by_user_auth_id INTEGER,
        by_on_behalf_of_user_auth_id INTEGER,
        by_on_behalf_of_user_name VARCHAR(255),
        generic_services JSONB DEFAULT '[]',
        data_index_increment INTEGER DEFAULT 0,
        has_logo BOOLEAN DEFAULT false
      );
    `);
    console.log('Database schema initialized');
  } catch (err) {
    console.error('Error initializing database:', err);
    throw err; // Ensure startup fails if initialization fails
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
  const serviceId = `database-${Date.now()}`; 
  const maxRetries = 5;
  let attempt = 0;

  while (attempt < maxRetries) {
    try {
      await registerServiceWithConsul({
        ID: serviceId,
        Name: 'database-service', 
        Address: process.env.HOSTNAME || 'database-service',
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

// GET /database/{id}
app.get('/database/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('SELECT * FROM databases WHERE id = $1', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Database not found' });
    }
    const dbInfo = result.rows[0];
    res.status(200).json({
      id: dbInfo.id,
      version: dbInfo.version,
      name: dbInfo.name,
      description: dbInfo.description,
      institution: dbInfo.institution,
      numberFormat: dbInfo.number_format,
      schema: dbInfo.schema,
      schemaTags: dbInfo.schema_tags,
      schemaFlags: dbInfo.schema_flags,
      fieldsUniques: dbInfo.fields_uniques,
      isDraft: dbInfo.is_draft,
      isDisabled: dbInfo.is_disabled,
      isArchived: dbInfo.is_archived,
      modifiedAt: dbInfo.modified_at,
      byUserName: dbInfo.by_user_name,
      byUserAuthId: dbInfo.by_user_auth_id,
      byOnBehalfOfUserAuthId: dbInfo.by_on_behalf_of_user_auth_id,
      byOnBehalfOfUserName: dbInfo.by_on_behalf_of_user_name,
      genericServices: dbInfo.generic_services,
      dataIndexIncrement: dbInfo.data_index_increment,
      hasLogo: dbInfo.has_logo,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /database/{id}
app.delete('/database/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('DELETE FROM databases WHERE id = $1', [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Database not found' });
    }
    res.status(200).json('Success');
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /database/modify
app.post('/database/modify', authenticateToken, async (req, res) => {
  const { groupName, catalogName, code, schema } = req.body;

  if (!groupName || !catalogName || !code || !schema || !schema.creationDate || !schema.description || !schema.filename) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const result = await pool.query(`
      INSERT INTO databases (group_name, catalog_name, code, name, description, schema, modified_at)
      VALUES ($1, $2, $3, $4, $5, $6, NOW())
      ON CONFLICT (code) DO UPDATE
      SET group_name = $1, catalog_name = $2, name = $4, description = $5, schema = $6, modified_at = NOW()
      RETURNING schema
    `, [groupName, catalogName, code, catalogName, schema.description, schema]);

    res.status(200).json(result.rows[0].schema);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /databases
app.get('/databases', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM databases');
    const databases = result.rows.map(db => ({
      id: db.id,
      version: db.version,
      name: db.name,
      code: db.code,
      description: db.description,
      institution: db.institution,
      numberFormat: db.number_format,
      schema: db.schema,
      schemaTags: db.schema_tags,
      schemaFlags: db.schema_flags,
      fieldsUniques: db.fields_uniques,
      isDraft: db.is_draft,
      isDisabled: db.is_disabled,
      isArchived: db.is_archived,
      modifiedAt: db.modified_at,
      byUserName: db.by_user_name,
      byUserAuthId: db.by_user_auth_id,
      byOnBehalfOfUserAuthId: db.by_on_behalf_of_user_auth_id,
      byOnBehalfOfUserName: db.by_on_behalf_of_user_name,
      genericServices: db.generic_services,
      dataIndexIncrement: db.data_index_increment,
      hasLogo: db.has_logo,
    }));

    const groupedDatabases = {
      id: 1,
      name: 'Digital Registries',
      code: 'DR',
      databases,
      groupId: 1,
      order: 1,
      dataIndexIncrement: 0,
    };

    res.status(200).json(groupedDatabases);
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
      console.log(`Datatbase Service running on dynamically assigned port ${port}`);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

startServer();