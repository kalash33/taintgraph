# Taintgraph: API, agents and the built web app. Runs two ways:
#  - beside FalkorDB (docker-compose.yml sets FALKORDB_URL), or
#  - on its own, with FalkorDB embedded on localhost (no FALKORDB_URL; e.g. Render's free plan).
FROM node:24-slim AS build
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY server/package.json server/
COPY web/package.json web/
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm build

FROM falkordb/falkordb:v4.22.1
COPY --from=build /usr/local/bin/node /usr/local/bin/node
COPY --from=build /app /app
COPY scripts/start.sh /usr/local/bin/taintgraph-start
RUN chmod +x /usr/local/bin/taintgraph-start
ENV NODE_ENV=production PORT=8787 TRUST_PROXY=1 BROWSER=0
EXPOSE 8787
WORKDIR /app/server
ENTRYPOINT []
CMD ["taintgraph-start"]
