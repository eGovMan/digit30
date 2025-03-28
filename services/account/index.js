const express = require('express');
const { Pool } = require('pg');
const fetch = require('node-fetch');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors({ origin: true }));

const pool = new Pool({
  user: process.env.POSTGRES_USER || 'admin',
  host: process.env.POSTGRES_HOST || 'postgres',
  database: process.env.POSTGRES_DB || 'registry',
  password: process.env.POSTGRES_PASSWORD || 'password',
  port: 5432,
});

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS accounts (
      id SERIAL PRIMARY KEY,
      accountname VARCHAR(255) UNIQUE NOT NULL,
      admin_email VARCHAR(255),
      admin_phone VARCHAR(255),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  console.log('Accounts table initialized');
}

initializeDatabase();

// Check if accountname exists
app.get('/check-account', async (req, res) => {
  const { accountname } = req.query;
  if (!accountname) {
    return res.status(400).json({ error: 'Account name required' });
  }
  try {
    const result = await pool.query('SELECT 1 FROM accounts WHERE accountname = $1', [accountname]);
    res.json({ exists: result.rowCount > 0 });
  } catch (err) {
    console.error('Error checking account:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create new account and Keycloak realm
app.post('/create-account', async (req, res) => {
  const { accountname, adminEmail, adminPhone, password } = req.body;
  if (!accountname || !adminEmail || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    // Check if accountname exists
    const checkResult = await pool.query('SELECT 1 FROM accounts WHERE accountname = $1', [accountname]);
    if (checkResult.rowCount > 0) {
      return res.status(409).json({ error: 'Account name already exists' });
    }

    // Get Keycloak admin token
    const tokenResponse = await fetch(`${process.env.KEYCLOAK_ADMIN_URL}/realms/master/protocol/openid-connect/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'password',
        client_id: 'admin-cli',
        username: process.env.KEYCLOAK_ADMIN_USERNAME || 'admin',
        password: process.env.KEYCLOAK_ADMIN_PASSWORD || 'admin',
      }),
    });
    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok) {
      throw new Error('Failed to get admin token: ' + tokenData.error);
    }
    const adminToken = tokenData.access_token;

    // Create Keycloak realm
    const realmResponse = await fetch(`${process.env.KEYCLOAK_ADMIN_URL}/admin/realms`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${adminToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        realm: accountname,
        enabled: true,
        id: accountname,
      }),
    });
    if (!realmResponse.ok) {
      const errorText = await realmResponse.text();
      throw new Error('Failed to create realm: ' + errorText);
    }

    // Create admin user in the new realm
    const userResponse = await fetch(`${process.env.KEYCLOAK_ADMIN_URL}/admin/realms/${accountname}/users`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${adminToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username: 'admin',
        email: adminEmail,
        enabled: true,
        credentials: [{ type: 'password', value: password, temporary: false }],
      }),
    });
    if (!userResponse.ok) {
      throw new Error('Failed to create admin user');
    }

    // Create client in the new realm
    const clientResponse = await fetch(`${process.env.KEYCLOAK_ADMIN_URL}/admin/realms/${accountname}/clients`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${adminToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          clientId: `${accountname}-client`,
          enabled: true,
          publicClient: true,
          redirectUris: ['http://localhost:3001/*', 'http://localhost:11000/callback'], // Add callback URI
          protocol: 'openid-connect',
        }),
      });
    if (!clientResponse.ok) {
      throw new Error('Failed to create client');
    }

    // Store account details
    await pool.query(
      'INSERT INTO accounts (accountname, admin_email, admin_phone) VALUES ($1, $2, $3)',
      [accountname, adminEmail, adminPhone || null]
    );

    res.status(201).json({ message: 'Account created', accountname });
  } catch (err) {
    console.error('Error creating account:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

const PORT = process.env.PORT || 12000;
app.listen(PORT, () => console.log(`Account Service running on port ${PORT}`));