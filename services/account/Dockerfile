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
    KEYCLOAK_BASE_URL=http://localhost:8080 \
    KEYCLOAK_ADMIN_URL=http://localhost:8080 \
    KEYCLOAK_ADMIN_USERNAME=admin \
    KEYCLOAK_ADMIN_PASSWORD=admin \
    HOSTNAME=account-service
CMD ["npm", "start"]