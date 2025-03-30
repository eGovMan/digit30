const express = require('express');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const fetch = require('node-fetch');
const cors = require('cors');


const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
  origin: true,
  credentials: true
}));

const KEYCLOAK_HOST_URL = process.env.KEYCLOAK_HOST_URL || 'http://host.docker.internal:8080';
const CONSUL_HOST = process.env.CONSUL_HOST || 'consul';
const CONSUL_PORT = process.env.CONSUL_PORT || 8500;


const getJwksClient = (realm) => jwksClient({
  jwksUri: `${KEYCLOAK_HOST_URL}/realms/${realm}/protocol/openid-connect/certs`,
});

function getKey(realm) {
  return (header, callback) => {
    const client = getJwksClient(realm);
    client.getSigningKey(header.kid, (err, key) => {
      const signingKey = key?.publicKey || key?.rsaPublicKey;
      callback(err, signingKey);
    });
  };
}

function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ responseTime: new Date().toISOString(), errors: [{ errorCode: 'invalid_request', errorMessage: 'Authorization token required' }] });
  }
  const token = authHeader.split(' ')[1];
  const realm = req.query.realm || req.body.realm || 'digit30';
  jwt.verify(token, getKey(realm), {
    issuer: `${KEYCLOAK_HOST_URL}/realms/${realm}`,
    audience: 'account',
  }, (err, decoded) => {
    if (err) {
      console.error('Token verification failed:', err.message);
      return res.status(401).json({ responseTime: new Date().toISOString(), errors: [{ errorCode: 'invalid_token', errorMessage: 'Invalid or expired token' }] });
    }
    req.decodedToken = decoded;
    console.log(`Decoded token for realm ${realm}: ${JSON.stringify(decoded)}`);
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
  const serviceId = `identity-${Date.now()}`; 
  const maxRetries = 5;
  let attempt = 0;

  while (attempt < maxRetries) {
    try {
      await registerServiceWithConsul({
        ID: serviceId,
        Name: 'identity-service', 
        Address: process.env.HOSTNAME || 'identity-service',
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

app.get('/authorize', (req, res) => {
  const { scope, response_type, client_id, redirect_uri, state, nonce, realm, username } = req.query;

  if (!scope || !response_type || !client_id || !redirect_uri || !realm) {
    console.error('Missing required query parameters:', { scope, response_type, client_id, redirect_uri, realm });
    return res.status(400).send('Missing required query parameters');
  }

  if (response_type !== 'code') {
    console.error('Unsupported response_type:', response_type);
    return res.status(400).send('Unsupported response_type');
  }

  const keycloakAuthUrl = `${KEYCLOAK_HOST_URL}/realms/${realm}/protocol/openid-connect/auth?` +
    `response_type=${encodeURIComponent(response_type)}&` +
    `client_id=${encodeURIComponent(client_id)}&` +
    `redirect_uri=${encodeURIComponent(redirect_uri)}&` +
    `scope=${encodeURIComponent(scope)}&` +
    `state=${encodeURIComponent(state || '')}&` +
    (nonce ? `nonce=${encodeURIComponent(nonce)}&` : '') +
    (username ? `login_hint=${encodeURIComponent(username)}` : '');

  console.log(`Redirecting to Keycloak: ${keycloakAuthUrl}`);
  res.redirect(keycloakAuthUrl);
});

app.post('/oauth/token', async (req, res) => {
  const { grant_type, code, client_id, redirect_uri, refresh_token, realm } = req.body;

  if (!realm) {
    console.error('Realm missing in token request');
    return res.status(400).json({ error: 'invalid_request', error_description: 'Realm is required' });
  }

  if (grant_type === 'authorization_code' && (!code || !client_id || !redirect_uri)) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Missing required fields for authorization_code' });
  }

  if (grant_type === 'refresh_token' && (!refresh_token || !client_id)) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Missing required fields for refresh_token' });
  }

  if (!['authorization_code', 'refresh_token'].includes(grant_type)) {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  try {
    const tokenResponse = await fetch(`${KEYCLOAK_HOST_URL}/realms/${realm}/protocol/openid-connect/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type,
        ...(grant_type === 'authorization_code' ? { code, client_id, redirect_uri } : {}),
        ...(grant_type === 'refresh_token' ? { refresh_token, client_id } : {}),
      }),
    });

    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok) {
      console.error(`Token exchange failed for realm ${realm}:`, tokenData);
      return res.status(400).json(tokenData);
    }

    console.log(`Token exchange successful for realm ${realm}:`, tokenData);
    res.status(200).json(tokenData);
  } catch (error) {
    console.error('Token exchange error:', error);
    res.status(500).json({ error: 'server_error', error_description: 'Failed to exchange token' });
  }
});

async function startServer() {
  try {
    const server = app.listen(0, async () => {
      const port = server.address().port; // Corrected to use server object
      await registerService(port);
      console.log(`Identity Service running on dynamically assigned port ${port}`);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

startServer();