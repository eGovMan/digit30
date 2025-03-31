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
const CONSUL_HOST = process.env.CONSUL_HOST || 'consul';
const CONSUL_PORT = process.env.CONSUL_PORT || 8500;

async function initializeDatabase() {
    try {
        const tableExists = await pool.query(`
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'accounts'
            );
        `);
        const exists = tableExists.rows[0].exists;

        if (!exists) {
            await pool.query(`
                CREATE TABLE accounts (
                    id SERIAL PRIMARY KEY,
                    accountname VARCHAR(255) UNIQUE NOT NULL,
                    admin_email VARCHAR(255),
                    admin_phone VARCHAR(255),
                    config JSONB NOT NULL,  -- Store all configuration as JSONB
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
            `);
            console.log('Accounts table created with config column');
        } else {
            const configExists = await pool.query(`
                SELECT EXISTS (
                    SELECT FROM information_schema.columns 
                    WHERE table_schema = 'public' 
                    AND table_name = 'accounts' 
                    AND column_name = 'config'
                );
            `);
            if (!configExists.rows[0].exists) {
                await pool.query(`
                    ALTER TABLE accounts 
                    ADD COLUMN config JSONB NOT NULL DEFAULT '{}';
                `);
                console.log('Added config column to accounts table');
            }
        }
    } catch (err) {
        console.error('Error initializing database:', err);
        throw err;
    }
}

async function registerServiceWithConsul({ ID, Name, Address, Port }) {
    const maxRetries = 5;
    let attempt = 0;

    while (attempt < maxRetries) {
        try {
            const response = await fetch(`http://${CONSUL_HOST}:${CONSUL_PORT}/v1/agent/service/register`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ID, Name, Address, Port })
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
    const serviceId = `account-${Date.now()}`;
    await registerServiceWithConsul({
        ID: serviceId,
        Name: 'account-service',
        Address: process.env.HOSTNAME || 'account-service',
        Port: port
    });

    process.on('SIGINT', async () => {
        await deregisterServiceFromConsul(serviceId);
        console.log(`Deregistered ${serviceId} from Consul`);
        process.exit();
    });
}

// Health check endpoint
app.get('/health', (req, res) => res.status(200).json({ status: 'healthy' }));

// Get full account details including config
app.get('/client/:accountname', async (req, res) => {
    const { accountname } = req.params;
    try {
        const result = await pool.query(
            'SELECT accountname, admin_email, admin_phone, config FROM accounts WHERE accountname = $1',
            [accountname]
        );
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Account not found' });
        }
        const account = result.rows[0];
        res.json({
            accountname: account.accountname,
            adminEmail: account.admin_email,
            adminPhone: account.admin_phone,
            ...account.config // Spread config fields (oidc, models, textEmbeddingModels)
        });
    } catch (err) {
        console.error('Error fetching client details:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update account configuration (accountname is immutable)
app.put('/client/:accountname', async (req, res) => {
    const { accountname } = req.params;
    const { adminEmail, adminPhone, oidc, models, textEmbeddingModels } = req.body;

    try {
        const result = await pool.query(
            'SELECT 1 FROM accounts WHERE accountname = $1',
            [accountname]
        );
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Account not found' });
        }

        const config = {
            oidc: oidc || {},
            models: models || [],
            textEmbeddingModels: textEmbeddingModels || []
        };

        const updateResult = await pool.query(
            'UPDATE accounts SET admin_email = $1, admin_phone = $2, config = $3 WHERE accountname = $4 RETURNING *',
            [adminEmail || null, adminPhone || null, JSON.stringify(config), accountname]
        );

        const updatedAccount = updateResult.rows[0];
        res.json({
            accountname: updatedAccount.accountname,
            adminEmail: updatedAccount.admin_email,
            adminPhone: updatedAccount.admin_phone,
            ...updatedAccount.config
        });
    } catch (err) {
        console.error('Error updating account:', err);
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
        const checkResult = await pool.query('SELECT 1 FROM accounts WHERE accountname = $1', [accountname]);
        if (checkResult.rowCount > 0) {
            return res.status(409).json({ error: 'Account name already exists' });
        }

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
            console.error('Token response:', tokenData);
            throw new Error('Failed to get admin token: ' + tokenData.error);
        }
        const adminToken = tokenData.access_token;

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
                redirectUris: ['http://localhost:3002/login/callback', 'http://localhost:5173/login/callback'],
                protocol: 'openid-connect',
            }),
        });
        if (!clientResponse.ok) {
            throw new Error('Failed to create client');
        }

        const config = {
            oidc: {
                authUrl: `${KEYCLOAK_BASE_URL}/realms/${accountname}/protocol/openid-connect/auth?client_id=${clientId}&response_type=code&redirect_uri=http://localhost:3002/login/callback&scope=openid profile email`,
                clientId,
                resource,
                scopes: "openid profile email",
                redirectUri: "http://localhost:3002/login/callback",
                nameClaim: "name",
                tolerance: "0"
            },
            models: [
                {
                    name: "microsoft/Phi-3-mini-4k-instruct",
                    endpoints: [{ type: "llamacpp", baseURL: "http://llama-server:8082" }],
                    description: "Phi-3-mini model running locally via llama.cpp",
                    promptExamples: [
                        { title: "Configure a Registry", prompt: "..." },
                        { title: "Find and Apply for a Service", prompt: "..." },
                        { title: "File a Complaint", prompt: "..." }
                    ]
                }
            ],
            textEmbeddingModels: [
                {
                    name: "Xenova/gte-small",
                    displayName: "Xenova/gte-small",
                    description: "Local embedding model running on the server.",
                    chunkCharLength: 512,
                    endpoints: [{ type: "transformersjs" }]
                }
            ]
        };

        await pool.query(
            'INSERT INTO accounts (accountname, admin_email, admin_phone, config) VALUES ($1, $2, $3, $4)',
            [accountname, adminEmail, adminPhone || null, JSON.stringify(config)]
        );

        res.status(201).json({ message: 'Account created', accountname, config });
    } catch (err) {
        console.error('Error creating account:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Initialize and start the server
async function startServer() {
    try {
        await initializeDatabase();
        const server = app.listen(0, async () => {
            const port = server.address().port;
            await registerService(port);
            console.log(`Account Service running on dynamically assigned port ${port}`);
        });
    } catch (err) {
        console.error('Failed to start server:', err);
        process.exit(1);
    }
}

startServer();