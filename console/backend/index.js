const express = require('express');
const fetch = require('node-fetch');
const cookieParser = require('cookie-parser');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: 'http://localhost:3001',
  credentials: true
}));

const IDENTITY_TOKEN_URL = 'http://host.docker.internal:4000/oauth/token';
const REDIRECT_URI = 'http://localhost:11000/callback';

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

  const authUrl = `http://host.docker.internal:4000/authorize?scope=${encodeURIComponent(scope)}&response_type=${encodeURIComponent(response_type)}&client_id=${encodeURIComponent(client_id)}&redirect_uri=${encodeURIComponent(redirect_uri)}&state=${encodeURIComponent(state || '')}&${nonce ? `nonce=${encodeURIComponent(nonce)}&` : ''}realm=${encodeURIComponent(realm)}&username=${encodeURIComponent(username || '')}`;
  console.log(`Redirecting to authorize: ${authUrl}`);
  res.redirect(authUrl);
});

app.get('/callback', async (req, res) => {
  console.log('Received callback request:', req.query);

  const { code, state, realm: queryRealm, iss } = req.query;

  if (state !== 'xyz') {
    console.error('Invalid state:', state);
    return res.status(400).send('Invalid state parameter');
  }

  let realm = queryRealm;
  if (!realm && iss) {
    try {
      const issUrl = new URL(iss);
      realm = issUrl.pathname.split('/realms/')[1];
      console.log(`Extracted realm from iss: ${realm}`);
    } catch (error) {
      console.error('Failed to parse iss:', iss, error);
    }
  }

  if (!realm) {
    console.error('No realm specified in query or iss:', req.query);
    return res.status(400).send('Realm not specified');
  }

  try {
    const clientId = `${realm}-client`;
    console.log(`Fetching token for realm: ${realm}, client: ${clientId}`);
    const tokenResponse = await fetch(IDENTITY_TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: clientId,
        redirect_uri: REDIRECT_URI,
        code,
        realm: realm,
      }),
    });

    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok) {
      console.error(`Token exchange failed for realm ${realm}:`, tokenData);
      return res.status(400).send(`Authentication failed: ${JSON.stringify(tokenData)}`);
    }

    console.log('Token data received:', tokenData);

    res.cookie(`access_token_${realm}`, tokenData.access_token, {
      httpOnly: true,
      secure: false,
      sameSite: 'Lax',
    });
    res.cookie(`refresh_token_${realm}`, tokenData.refresh_token, {
      httpOnly: true,
      secure: false,
      sameSite: 'Lax',
    });
    res.cookie('realm', realm, { httpOnly: true, secure: false, sameSite: 'Lax' });

    console.log(`Cookies set: access_token_${realm}, refresh_token_${realm}, realm`);
    res.redirect('http://localhost:3001');
  } catch (error) {
    console.error('Callback error:', error.message);
    res.status(500).send('Internal server error during callback');
  }
});

app.get('/auth/status', async (req, res) => {
  const realm = req.cookies.realm;
  if (!realm) {
    console.log('No realm cookie found');
    return res.status(403).json({ error: 'No realm specified in session' });
  }
  console.log('Checking auth status, realm:', realm);
  console.log('Cookies received:', req.cookies);

  const accessToken = req.cookies[`access_token_${realm}`];
  if (accessToken) {
    console.log(`Found access token for ${realm}:`, accessToken);
    res.json({ token: accessToken, realm });
  } else {
    console.log(`No access token found for realm ${realm}`);
    return res.status(403).json({ error: 'No valid session' });
  }
});

app.get('/refresh', async (req, res) => {
  const realm = req.cookies.realm;
  if (!realm) {
    console.error('No realm specified in session');
    return res.status(403).json({ error: 'No realm specified in session' });
  }

  const refreshToken = req.cookies[`refresh_token_${realm}`];
  if (!refreshToken) {
    console.error('No refresh token available');
    return res.status(403).json({ error: 'No refresh token available' });
  }

  try {
    const clientId = `${realm}-client`;
    console.log(`Refreshing token for realm: ${realm}`);
    const refreshResponse = await fetch(IDENTITY_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: clientId,
        refresh_token: refreshToken,
        realm: realm,
      }),
    });

    const refreshData = await refreshResponse.json();
    if (!refreshResponse.ok) {
      console.error(`Refresh failed for realm ${realm}:`, refreshData);
      res.clearCookie(`access_token_${realm}`);
      res.clearCookie(`refresh_token_${realm}`);
      res.clearCookie('realm');
      return res.status(401).json({ error: 'Refresh token invalid or expired' });
    }

    res.cookie(`access_token_${realm}`, refreshData.access_token, { httpOnly: true, secure: false, sameSite: 'Lax' });
    res.cookie(`refresh_token_${realm}`, refreshData.refresh_token, { httpOnly: true, secure: false, sameSite: 'Lax' });
    res.json({ token: refreshData.access_token, realm });
  } catch (error) {
    console.error('Refresh error:', error);
    res.status(500).json({ error: 'Internal server error during refresh' });
  }
});

app.get('/logout', (req, res) => {
  const realm = req.cookies.realm;
  if (realm) {
    res.clearCookie(`access_token_${realm}`);
    res.clearCookie(`refresh_token_${realm}`);
    res.clearCookie('realm');
  }
  res.redirect('http://localhost:3001');
});

const port = 11000;
app.listen(port, () => {
  console.log(`Backend Service running on port ${port}`);
});