#!/usr/bin/env bash
set -e
echo "Starting backend via docker-compose..."
docker-compose up --build -d
echo "Backend should be at http://127.0.0.1:5000"
echo "Reload extension in chrome://extensions -> Reload"
