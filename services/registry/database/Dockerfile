FROM node:18-alpine
RUN apk add --no-cache curl
WORKDIR /usr/src/app
COPY package.json ./
RUN npm install
COPY . .
EXPOSE 5001
CMD ["npm", "start"]