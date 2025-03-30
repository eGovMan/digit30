const express = require('express');
const fetch = require('node-fetch');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');

const CONSUL_HOST = process.env.CONSUL_HOST || 'consul';
const CONSUL_PORT = process.env.CONSUL_PORT || 8500;


const app = express();
app.use(express.json());
app.use(cors({
  origin: true,
  credentials: true
}));


const client = jwksClient({
  jwksUri: process.env.KEYCLOAK_JWKS_URI || 'http://keycloak:8080/realms/digit30/protocol/openid-connect/certs',
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
  const serviceId = `enrollment-${uuidv4()}`;
  const maxRetries = 5;
  let attempt = 0;

  while (attempt < maxRetries) {
    try {
      await registerServiceWithConsul({
        ID: serviceId,
        Name: 'enrollment-service',
        Address: process.env.HOSTNAME || 'enrollment-service',
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
        console.error(`Failed to register with Consul after ${maxRetries} attempts: ${err.message}`);
      }
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }
}

// Health check endpoint
app.get('/health', (req, res) => res.status(200).json({ status: 'healthy' }));

app.put('/enrollment', authenticateToken, async (req, res) => {
  const { id, version, request } = req.body;

  if (!id || !version || !request || !request.id) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    // Discover registry-service via Consul
    const services = await consul.catalog.service.nodes('registry-service');
    if (!services.length) throw new Error('Registry service not found');
    const { Address, ServicePort } = services[0]; // Use first available instance
    const registryUrl = `http://${Address}:${ServicePort}/data/MCTS/1.0/createEntries`;

    const registryResponse = await fetch(registryUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${req.headers['authorization'].split(' ')[1]}`,
        'Content-Type': 'application/json',
        'Information-Mediator-Client': 'eGovStack/GOV/90000009/eregistrations-dev',
      },
      body: JSON.stringify({
        write: [{
          content: {
            id: request.id,
            child: { citizenId: request.id, firstName: 'Enrolled User' },
            enrollmentDetails: { source: request.source, process: request.process, refId: request.refId },
          },
        }],
      }),
    });

    if (!registryResponse.ok) {
      throw new Error(`Registry update failed: ${registryResponse.status} - ${await registryResponse.text()}`);
    }

    const registryData = await registryResponse.json();
    res.status(200).send(`Enrollment recorded: ${JSON.stringify(registryData)}`);
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
      console.log(`Enrollment Service running on dynamically assigned port ${port}`);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

startServer();