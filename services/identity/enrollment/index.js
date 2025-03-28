const express = require('express');
const fetch = require('node-fetch');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const cors = require('cors'); 

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
  console.log('Received token:', token); // Log token

  jwt.verify(token, getKey, {
    issuer: process.env.KEYCLOAK_ISSUER || 'http://localhost:8080/realms/digit30',
    audience: process.env.KEYCLOAK_AUDIENCE || 'account',
  }, (err, decoded) => {
    if (err) {
      console.error('Token verification failed:', err.message); // Detailed error
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    console.log('Token decoded:', decoded); // Successful decode
    req.user = decoded;
    next();
  });
}

app.put('/enrollment', authenticateToken, async (req, res) => {
  const { id, version, request } = req.body;

  if (!id || !version || !request || !request.id) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const registryResponse = await fetch('http://host.docker.internal:6000/data/MCTS/1.0/createEntries', {
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

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Enrollment Service running on port ${PORT}`);
});