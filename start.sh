#!/bin/bash
# Fallback to port 8080 if Railway does not inject $PORT
export PORT=${PORT:-8080}
echo "Starting Uvicorn on 0.0.0.0:$PORT with proxy headers"
exec uvicorn sentinal_fuzz.web.app:create_app --factory --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips='*'
