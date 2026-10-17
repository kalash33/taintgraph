# Deploying

Taintgraph is one container plus FalkorDB. Anything that runs two containers and a volume works.

## Docker Compose (any VM)

```bash
git clone https://github.com/kalash33/taintgraph && cd taintgraph
cp .env.example .env     # optional model key
docker compose up -d --build
```

The app listens on `127.0.0.1:8787`; put a reverse proxy with TLS in front of it and set `TRUST_PROXY=1`. On first start, `TAINTGRAPH_SEED=1` scans the seven samples into the `demo` workspace (about 2–3 minutes with a cold cache; the app is usable meanwhile).

## Railway

1. **FalkorDB service.** New service → Docker image `falkordb/falkordb:v4.22.1`.
   - Add a volume at `/var/lib/falkordb/data`.
   - Set `REDIS_ARGS=--appendonly yes --requirepass <a long random password>`.
   - Don't give it a public domain.
2. **App service.** New service → this GitHub repo. `railway.json` builds the Dockerfile and health-checks `/api/health`. Variables:

   | Variable | Value |
   |---|---|
   | `FALKORDB_URL` | `redis://default:<password>@${{FalkorDB.RAILWAY_PRIVATE_DOMAIN}}:6379` |
   | `TAINTGRAPH_SEED` | `1` |
   | `TRUST_PROXY` | `1` |
   | `NVIDIA_API_KEY` or `OPENROUTER_API_KEY` | optional |

3. Generate a public domain for the app service.

## Before exposing it publicly

- FalkorDB must have a password and no public port.
- The workspace header separates data but doesn't authenticate anyone; anyone with the URL can scan and ask. Rate limits apply per IP (10 scans and 20 questions a minute). A model key on a public demo will be spent by visitors' questions.
- `/api/health` reports whether FalkorDB and a model are reachable; use it for uptime checks.
