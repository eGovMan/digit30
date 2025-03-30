const fetch = require('node-fetch');

const CONSUL_HOST = 'consul';
const CONSUL_PORT = 8500;
const KONG_ADMIN_URL = 'http://kong:8001';

async function waitForKongAdmin() {
  const maxAttempts = 30; // Wait up to 60 seconds (30 * 2s)
  let attempts = 0;

  while (attempts < maxAttempts) {
    try {
      const response = await fetch(`${KONG_ADMIN_URL}/status`);
      if (response.ok) {
        console.log('Kong Admin API is ready');
        return;
      }
    } catch (err) {
      console.log(`Waiting for Kong Admin API... (${attempts + 1}/${maxAttempts})`);
    }
    await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds
    attempts++;
  }
  throw new Error('Kong Admin API not ready after maximum attempts');
}

async function syncServices() {
  try {
    // Fetch services from Consul
    const consulResponse = await fetch(`http://${CONSUL_HOST}:${CONSUL_PORT}/v1/agent/services`);
    if (!consulResponse.ok) {
      throw new Error(`Consul request failed: ${consulResponse.status} ${await consulResponse.text()}`);
    }
    const services = await consulResponse.json();

    // Register each service in Kong
    for (const [serviceId, service] of Object.entries(services)) {
      const serviceName = service.Service;
      const serviceHost = service.Address || serviceName;
      const servicePort = service.Port;

      // Check if service exists in Kong
      const kongServiceCheck = await fetch(`${KONG_ADMIN_URL}/services/${serviceName}`);
      if (kongServiceCheck.status === 404) {
        await fetch(`${KONG_ADMIN_URL}/services`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: serviceName,
            host: serviceHost,
            port: servicePort,
            protocol: 'http'
          })
        });
        console.log(`Registered service: ${serviceName}`);
      }

      // Add a route based on service name
      const kongRouteCheck = await fetch(`${KONG_ADMIN_URL}/services/${serviceName}/routes`);
      const routes = await kongRouteCheck.json();
      if (!routes.data.some(route => route.paths.includes(`/${serviceName}`))) {
        await fetch(`${KONG_ADMIN_URL}/services/${serviceName}/routes`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            paths: [`/${serviceName}`]
          })
        });
        console.log(`Added route: /${serviceName}`);
      }
    }
  } catch (err) {
    console.error('Error syncing services:', err);
  }
}

async function syncServicesContinuously() {
  await waitForKongAdmin(); // Wait for Kong Admin API to be ready
  while (true) {
    await syncServices();
    await new Promise(resolve => setTimeout(resolve, 60000)); // Sync every 60 seconds
  }
}

syncServicesContinuously().catch(err => console.error('Error:', err));