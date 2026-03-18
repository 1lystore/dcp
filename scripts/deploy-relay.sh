#!/bin/bash
# DCP Relay Deployment Script
# Usage: ./scripts/deploy-relay.sh [production|staging]

set -e

ENVIRONMENT=${1:-staging}
RELAY_PORT=${DCP_RELAY_PORT:-8421}
RELAY_HOST=${DCP_RELAY_HOST:-"relay.dcp.1ly.store"}

echo "🚀 Deploying DCP Relay to $ENVIRONMENT..."

# Build the relay package
echo "📦 Building @dcprotocol/relay..."
npm run build -w @dcprotocol/relay

# Run tests
echo "🧪 Running tests..."
npm run test -w @dcprotocol/relay

# Create Docker image (if Docker is available)
if command -v docker &> /dev/null; then
    echo "🐳 Building Docker image..."

    cat > /tmp/dcp-relay.Dockerfile << 'EOF'
FROM node:20-alpine

WORKDIR /app

# Install the relay package globally
RUN npm install -g @dcprotocol/relay

# Expose default port
EXPOSE 8421

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -q --spider http://localhost:8421/health || exit 1

# Run relay
CMD ["npx", "@dcprotocol/relay", "--host", "0.0.0.0"]
EOF

    docker build -f /tmp/dcp-relay.Dockerfile -t dcprotocol/relay:latest .
    rm /tmp/dcp-relay.Dockerfile

    echo "✅ Docker image built: dcprotocol/relay:latest"
fi

# Generate systemd service file
echo "📝 Generating systemd service file..."
cat > /tmp/dcp-relay.service << EOF
[Unit]
Description=DCP Relay Server
Documentation=https://github.com/1lystore/dcp
After=network.target

[Service]
Type=simple
User=dcp
WorkingDirectory=/opt/dcp-relay
ExecStart=/usr/bin/npx @dcprotocol/relay --port ${RELAY_PORT}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Environment
Environment=NODE_ENV=production
Environment=DCP_RELAY_PORT=${RELAY_PORT}
Environment=DCP_RELAY_RATE_LIMIT=60

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

echo "✅ Systemd service file created at /tmp/dcp-relay.service"

# Print deployment instructions
cat << EOF

📋 Deployment Instructions for $ENVIRONMENT:

1. Copy service file:
   sudo cp /tmp/dcp-relay.service /etc/systemd/system/dcp-relay.service

2. Create dcp user:
   sudo useradd -r -s /bin/false dcp

3. Install relay:
   sudo mkdir -p /opt/dcp-relay
   cd /opt/dcp-relay
   npm install @dcprotocol/relay

4. Enable and start service:
   sudo systemctl daemon-reload
   sudo systemctl enable dcp-relay
   sudo systemctl start dcp-relay

5. Check status:
   sudo systemctl status dcp-relay
   curl http://localhost:${RELAY_PORT}/health

6. Configure nginx (see packages/dcp-relay/README.md)

7. Set up TLS with certbot:
   sudo certbot --nginx -d ${RELAY_HOST}

8. Monitor with Prometheus:
   Scrape: http://localhost:${RELAY_PORT}/metrics?format=prometheus

EOF

echo "🎉 Deployment preparation complete!"
