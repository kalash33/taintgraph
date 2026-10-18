# Deploying

Taintgraph is one container plus FalkorDB. Anything that runs two containers and a volume works.

## Docker Compose (any VM)

```bash
git clone https://github.com/kalash33/taintgraph && cd taintgraph
cp .env.example .env     # optional model key
docker compose up -d --build
```

The app listens on `127.0.0.1:8787`; put a reverse proxy with TLS in front of it and set `TRUST_PROXY=1`. On first start, `TAINTGRAPH_SEED=1` scans the seven samples into the `demo` workspace (about 2–3 minutes with a cold cache; the app is usable meanwhile).

## Render (one free web service)

The same image runs FalkorDB inside the container when `FALKORDB_URL` is not set, and sizes itself for 512 MB. Tested under a 512 MB memory limit: the full end-to-end check passes, peaking at about 450 MB.

- **Blueprint:** in the Render dashboard, New → Blueprint → this repository. `render.yaml` creates the `taintgraph` web service on the free plan. Set `GEMINI_API_KEY` if you want the LLM Analyst.
- **CLI:**
  ```bash
  render services create --name taintgraph --type web_service --runtime docker --plan free \
    --repo https://github.com/kalash33/taintgraph --branch main --health-check-path /api/health \
    --env-var GEMINI_API_KEY=... --output json --confirm
  ```

The free plan sleeps after 15 minutes without traffic, and the data lives in the container. After a restart, the first request wakes it (about 30 to 60 seconds) and the samples are re-seeded within about two minutes.

## Railway or any VM with two containers

Run `falkordb/falkordb:v4.22.1` with a volume at `/var/lib/falkordb/data` and `REDIS_ARGS=--appendonly yes --requirepass <password>`, then this image with `FALKORDB_URL=redis://default:<password>@<falkordb-host>:6379` and `TAINTGRAPH_SEED=1`. `railway.json` builds the Dockerfile and health-checks `/api/health`.

## Before exposing it publicly

- FalkorDB must have a password and no public port.
- The workspace header separates data but doesn't authenticate anyone; anyone with the URL can scan and ask. Rate limits apply per IP (10 scans and 20 questions a minute). A model key on a public demo will be spent by visitors' questions.
- `/api/health` reports whether FalkorDB and a model are reachable; use it for uptime checks.
