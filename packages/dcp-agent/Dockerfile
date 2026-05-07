# DCP Agent Docker Image
#
# Build: docker build -t dcprotocol/agent .
#
# Usage with pairing grant:
#   docker run -e DCP_PAIR_GRANT=dcp_pair_v1_... dcprotocol/agent
#
# Usage with pre-configured volume:
#   docker run -v ~/.dcp:/root/.dcp dcprotocol/agent
#
# OpenClaw integration (docker-compose):
#   services:
#     openclaw:
#       volumes:
#         - dcp-config:/root/.dcp
#     dcp-agent:
#       image: dcprotocol/agent
#       volumes:
#         - dcp-config:/root/.dcp

FROM node:20-alpine

LABEL org.opencontainers.image.title="DCP Agent"
LABEL org.opencontainers.image.description="Secure secrets provider for AI agents"
LABEL org.opencontainers.image.source="https://github.com/1lystore/dcp"
LABEL org.opencontainers.image.vendor="DCP Protocol"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Install dcp-agent
RUN npm install -g @dcprotocol/agent

# Create config directory
RUN mkdir -p /root/.dcp/agents && chmod 700 /root/.dcp/agents

# Set working directory
WORKDIR /app

# Copy entrypoint script
COPY scripts/docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Environment variables
ENV DCP_PAIR_GRANT=""
ENV DCP_AGENT_MODE="secrets"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD dcp-agent status --json | grep -q '"configured": true' || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["secrets"]
