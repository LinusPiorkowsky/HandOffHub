#!/bin/bash
# start.sh - Startup script for Railway

# Set default port if not provided
PORT=${PORT:-8080}

echo "Starting HandoffHub on port $PORT"

# Run gunicorn with the port
exec gunicorn app:app \
    --bind 0.0.0.0:$PORT \
    --workers 2 \
    --threads 4 \
    --timeout 120 \
    --log-level info
