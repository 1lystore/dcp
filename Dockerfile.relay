FROM node:20-bookworm-slim AS build

WORKDIR /app

COPY package.json package-lock.json ./
COPY packages/dcp-relay/package.json packages/dcp-relay/package.json

RUN npm ci

COPY packages/dcp-relay packages/dcp-relay

RUN npm run build -w @dcprotocol/relay \
  && npm prune --omit=dev --workspaces --include-workspace-root=false


FROM node:20-bookworm-slim AS runtime

WORKDIR /app

ENV NODE_ENV=production
ENV DCP_RELAY_HOST=0.0.0.0
ENV DCP_RELAY_PORT=8421

COPY --from=build /app/package.json /app/package-lock.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/packages/dcp-relay ./packages/dcp-relay

EXPOSE 8421

CMD ["node", "packages/dcp-relay/dist/index.js"]
