FROM node:18-alpine
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install --production
COPY index.js .
EXPOSE 0
ENV NODE_ENV=production \
    CONSUL_HOST=consul \
    CONSUL_PORT=8500 \
    KEYCLOAK_HOST_URL=http://host.docker.internal:8080 \
    HOSTNAME=identity-service
CMD ["npm", "start"]