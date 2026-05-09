FROM node:22-bookworm-slim AS build

WORKDIR /app

RUN corepack enable

COPY . .

RUN pnpm install --frozen-lockfile --ignore-scripts

RUN pnpm --filter @dcprotocol/relay run build


FROM node:22-bookworm-slim AS runtime

WORKDIR /app

ENV NODE_ENV=production
ENV DCP_RELAY_HOST=0.0.0.0
ENV DCP_RELAY_PORT=8422

COPY --from=build /app/package.json /app/pnpm-lock.yaml /app/pnpm-workspace.yaml ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/packages/dcp-relay ./packages/dcp-relay

EXPOSE 8422

CMD ["node", "packages/dcp-relay/dist/index.js"]
