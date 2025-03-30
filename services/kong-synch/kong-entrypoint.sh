#!/bin/sh

# Debug environment variable
echo "KONG_NGINX_DAEMON=$KONG_NGINX_DAEMON"

# Wait for kong-db to be ready with a timeout
timeout=60
attempt=0
until pg_isready -h kong-db -p 5432 -U kong -d kong || [ $attempt -ge $timeout ]; do
  echo "Waiting for kong-db... ($attempt/$timeout)"
  sleep 2
  attempt=$((attempt + 2))
done

if [ $attempt -ge $timeout ]; then
  echo "Error: Timed out waiting for kong-db"
  exit 1
fi

# Bootstrap the database if not already done
kong migrations bootstrap
if [ $? -ne 0 ]; then
  echo "Error: Failed to bootstrap database"
  exit 1
fi

# Start Kong with verbose output and explicit foreground
echo "Starting Kong..."
exec kong start --vv