Enrollment Service
Overview
The Enrollment Service is a Node.js-based RESTful API designed to process enrollment requests, such as registering new entities (e.g., users or devices) in a system. It accepts PUT requests to the /enrollment endpoint, authenticates them using OAuth2 Bearer tokens issued by Keycloak, and returns a structured JSON response confirming the enrollment. This service is decoupled from Keycloak-specific middleware, using generic JWT validation for flexibility across identity providers.
Features
Endpoint: PUT /enrollment
Authentication: Validates OAuth2 Bearer tokens against Keycloak’s public keys.
Response: Returns a JSON object with enrollment details (e.g., ID, timestamp, metadata).
Deployment: Runs in a Docker container with configurable environment variables.
Prerequisites
Docker: For containerized deployment.
Docker Compose: To manage the service.
Node.js: If building locally (optional).
Keycloak: An instance running at http://localhost:8080 (or configurable URL) with:
Realm: digit30
Client: digit-admin (public client)
User: testuser with password testpass (or your credentials)
jq: For parsing JSON in token generation (optional).
Installation
1. Clone the Repository
bash
git clone <repository-url>
cd <repository-directory>/services/identity/enrollment
2. Set Up Directory Structure
Ensure the following files are in services/identity/enrollment/:
index.js: The service code (see Code (#code)).
Dockerfile: For building the Docker image.
package.json: Node.js dependencies.
docker-compose.yaml: Docker Compose configuration.
Dockerfile
Dockerfile
FROM node:18-alpine
RUN apk add --no-cache curl  # For debugging
WORKDIR /usr/src/app
COPY package.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["node", "index.js"]
package.json
json
{
  "name": "enrollment-service",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.17.1",
    "jsonwebtoken": "^9.0.2",
    "jwks-rsa": "^3.1.0"
  }
}
docker-compose.yaml
yaml
version: "3.8"
services:
  enrollment-service:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - PORT=3000
      - KEYCLOAK_JWKS_URI=http://keycloak:8080/realms/digit30/protocol/openid-connect/certs
      - KEYCLOAK_ISSUER=http://localhost:8080/realms/digit30
      - KEYCLOAK_AUDIENCE=account
    networks:
      - app-network

networks:
  app-network:
    driver: bridge
    name: app-network
3. Install Dependencies
bash
npm install
4. Build and Run
Start Keycloak (if not running):
bash
docker run -d --name keycloak -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:21.1.1 start-dev
Connect Keycloak to app-network:
bash
docker network connect app-network keycloak
Start the service:
bash
docker-compose up --build
Configuration
Environment Variables
Variable
Description
Default Value
NODE_ENV
Node environment (e.g., production)
production
PORT
Port the service listens on
3000
KEYCLOAK_JWKS_URI
Keycloak JWKS endpoint for public keys
http://keycloak:8080/realms/digit30/protocol/openid-connect/certs
KEYCLOAK_ISSUER
Expected token issuer
http://localhost:8080/realms/digit30
KEYCLOAK_AUDIENCE
Expected token audience
account
Keycloak Setup
Access Admin Console: http://localhost:8080/admin (login: admin/admin).
Create Realm: digit30.
Create Client:
Client ID: digit-admin
Client Type: Public
Valid Redirect URIs: http://localhost:3000/*
Create User:
Username: testuser
Password: testpass (Credentials tab, Temporary: Off)
Testing
1. Generate a Token
bash
curl -X POST \
  "http://localhost:8080/realms/digit30/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=digit-admin" \
  -d "username=testuser" \
  -d "password=testpass" \
  | jq -r '.access_token' > token.txt
2. Test the Endpoint
bash
curl -v -X PUT \
  "http://localhost:3000/enrollment" \
  -H "Authorization: Bearer $(cat token.txt)" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "test.enrollment",
    "version": "v1",
    "request": {
      "id": "user123",
      "source": "REGISTRATION_CLIENT",
      "process": "NEW",
      "refId": "ref456"
    }
  }'
Expected Response
json
{
  "id": "test.enrollment",
  "version": "v1",
  "responsetime": "2025-03-25T02:XX:XX.XXXZ",
  "metaData": {
    "data": "Enrollment processed successfully"
  },
  "response": [
    {
      "id": "user123",
      "packetName": "enrollmentPacket",
      "source": "REGISTRATION_CLIENT",
      "process": "NEW",
      "refId": "ref456",
      "schemaVersion": "v1",
      "signature": "",
      "encryptedHash": "",
      "providerName": "Keycloak",
      "providerVersion": "1.0",
      "creationDate": "2025-03-25T02:XX:XX.XXXZ"
    }
  ],
  "errors": []
}
Logs
Check logs for confirmation:
bash
docker-compose logs enrollment-service
Look for:
Decoded token: { sub: 'f0c3f921-...', aud: 'account', ... }
Received enrollment request: { id: 'test.enrollment', ... }
Troubleshooting
401 Unauthorized:
Audience Mismatch: If token aud isn’t "account", adjust KEYCLOAK_AUDIENCE or token request scope.
Token Expired: Regenerate with the token command.
ECONNREFUSED: Ensure both containers are on app-network:
bash
docker network inspect app-network
No Response: Verify service is running:
bash
docker ps | grep enrollment-service
