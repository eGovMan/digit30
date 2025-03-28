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

const PORT = process.env.PORT || 4000;
const KEYCLOAK_HOST_URL = process.env.KEYCLOAK_HOST_URL || 'http://host.docker.internal:8080'; // Ensure this is correct

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

  const keycloakAuthUrl = `http://localhost:8080/realms/${realm}/protocol/openid-connect/auth?` +
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

app.listen(PORT, () => {
  console.log(`Identity Service running on port ${PORT}`);
});