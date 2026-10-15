# Taintgraph: API, agents and the built web app in one image. FalkorDB runs beside it (docker-compose.yml).
FROM node:24-slim AS build
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY server/package.json server/
COPY web/package.json web/
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm build

FROM node:24-slim
WORKDIR /app
ENV NODE_ENV=production PORT=8787
COPY --from=build /app /app
USER node
EXPOSE 8787
WORKDIR /app/server
CMD ["node", "--import", "tsx", "src/index.ts"]
