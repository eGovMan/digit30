FROM node:18-alpine
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install --production
COPY index.js .
EXPOSE 0
ENV NODE_ENV=production \
    CONSUL_HOST=consul \
    CONSUL_PORT=8500 \
    POSTGRES_HOST=postgres \
    POSTGRES_USER=admin \
    POSTGRES_PASSWORD=password \
    POSTGRES_DB=registry \
    KEYCLOAK_JWKS_URI=http://host.docker.internal:8080/realms/digit30/protocol/openid-connect/certs \
    KEYCLOAK_ISSUER=http://localhost:8080/realms/digit30 \
    KEYCLOAK_AUDIENCE=account \
    HOSTNAME=registry-service
CMD ["npm", "start"]