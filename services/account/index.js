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

const KEYCLOAK_BASE_URL = process.env.KEYCLOAK_BASE_URL || 'http://localhost:8080';
const KEYCLOAK_ADMIN_URL = process.env.KEYCLOAK_ADMIN_URL || 'http://localhost:8080';

async function initializeDatabase() {
    try {
        // Check if the accounts table exists
        const tableExists = await pool.query(`
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'accounts'
            );
        `);
        const exists = tableExists.rows[0].exists;

        if (!exists) {
            // Create table if it doesn’t exist
            await pool.query(`
                CREATE TABLE accounts (
                    id SERIAL PRIMARY KEY,
                    accountname VARCHAR(255) UNIQUE NOT NULL,
                    admin_email VARCHAR(255),
                    admin_phone VARCHAR(255),
                    client_id VARCHAR(255) UNIQUE NOT NULL,
                    resource VARCHAR(255) NOT NULL,
                    auth_url TEXT NOT NULL,  -- Added auth_url column
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
            `);
            console.log('Accounts table created');
        } else {
            // Check and add client_id column if missing
            const clientIdExists = await pool.query(`
                SELECT EXISTS (
                    SELECT FROM information_schema.columns 
                    WHERE table_schema = 'public' 
                    AND table_name = 'accounts' 
                    AND column_name = 'client_id'
                );
            `);
            if (!clientIdExists.rows[0].exists) {
                await pool.query(`
                    ALTER TABLE accounts 
                    ADD COLUMN client_id VARCHAR(255) UNIQUE NOT NULL DEFAULT 'default-client';
                `);
                console.log('Added client_id column to accounts table');
            }

            // Check and add resource column if missing
            const resourceExists = await pool.query(`
                SELECT EXISTS (
                    SELECT FROM information_schema.columns 
                    WHERE table_schema = 'public' 
                    AND table_name = 'accounts' 
                    AND column_name = 'resource'
                );
            `);
            if (!resourceExists.rows[0].exists) {
                await pool.query(`
                    ALTER TABLE accounts 
                    ADD COLUMN resource VARCHAR(255) NOT NULL DEFAULT 'default-resource';
                `);
                console.log('Added resource column to accounts table');
            }

            // Check and add auth_url column if missing
            const authUrlExists = await pool.query(`
                SELECT EXISTS (
                    SELECT FROM information_schema.columns 
                    WHERE table_schema = 'public' 
                    AND table_name = 'accounts' 
                    AND column_name = 'auth_url'
                );
            `);
            if (!authUrlExists.rows[0].exists) {
                await pool.query(`
                    ALTER TABLE accounts 
                    ADD COLUMN auth_url TEXT NOT NULL DEFAULT '';
                `);
                console.log('Added auth_url column to accounts table');
            }
        }
    } catch (err) {
        console.error('Error initializing database:', err);
    }
}

initializeDatabase();

// Get client details for an account
app.get('/client/:accountname', async (req, res) => {
    const { accountname } = req.params;
    try {
        const result = await pool.query('SELECT accountname, client_id, resource, auth_url FROM accounts WHERE accountname = $1', [accountname]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Account not found' });
        }
        const { client_id, resource, auth_url } = result.rows[0];
        res.json({ realm: accountname, client_id, resource, authUrl: auth_url });
    } catch (err) {
        console.error('Error fetching client:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

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

    const clientId = `${accountname}-client`;
    const resource = `${accountname}-resource`;

    try {
        // Check if accountname exists
        const checkResult = await pool.query('SELECT 1 FROM accounts WHERE accountname = $1', [accountname]);
        if (checkResult.rowCount > 0) {
            return res.status(409).json({ error: 'Account name already exists' });
        }

        // Get Keycloak admin token
        const tokenResponse = await fetch(`${KEYCLOAK_ADMIN_URL}/realms/master/protocol/openid-connect/token`, {
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
        const realmResponse = await fetch(`${KEYCLOAK_ADMIN_URL}/admin/realms`, {
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
        const userResponse = await fetch(`${KEYCLOAK_ADMIN_URL}/admin/realms/${accountname}/users`, {
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

        // Create public client in the new realm
        const clientResponse = await fetch(`${KEYCLOAK_ADMIN_URL}/admin/realms/${accountname}/clients`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${adminToken}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                clientId: clientId,
                enabled: true,
                publicClient: true,
                redirectUris: ['http://localhost:5173/login/callback'],
                protocol: 'openid-connect',
            }),
        });
        if (!clientResponse.ok) {
            throw new Error('Failed to create client');
        }

        // Construct full Keycloak auth URL
        const authUrl = `${KEYCLOAK_BASE_URL}/realms/${accountname}/protocol/openid-connect/auth?client_id=${clientId}&response_type=code&redirect_uri=http://localhost:5173/login/callback&scope=openid profile email`;

        // Store account details including auth_url
        await pool.query(
            'INSERT INTO accounts (accountname, admin_email, admin_phone, client_id, resource, auth_url) VALUES ($1, $2, $3, $4, $5, $6)',
            [accountname, adminEmail, adminPhone || null, clientId, resource, authUrl]
        );

        res.status(201).json({ message: 'Account created', accountname, client_id: clientId, resource, authUrl });
    } catch (err) {
        console.error('Error creating account:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

const PORT = process.env.PORT || 12000;
app.listen(PORT, () => console.log(`Account Service running on port ${PORT}`));