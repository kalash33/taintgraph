#!/bin/sh
# With FALKORDB_URL set, use that FalkorDB. Without it, start FalkorDB inside this container on localhost and size the
# app for a small host (512 MB), then seed the demo workspace.
set -e
if [ -z "$FALKORDB_URL" ]; then
  mkdir -p "${FALKORDB_DATA_PATH:-/var/lib/falkordb/data}"
  redis-server --bind 127.0.0.1 --port 6379 --protected-mode yes --save "" --appendonly no \
    --dir "${FALKORDB_DATA_PATH:-/var/lib/falkordb/data}" \
    --loadmodule "${FALKORDB_BIN_PATH:-/var/lib/falkordb/bin}/falkordb.so" ${FALKORDB_ARGS} &
  for i in $(seq 1 50); do
    redis-cli -h 127.0.0.1 ping >/dev/null 2>&1 && break
    sleep 0.2
  done
  export FALKORDB_URL=redis://127.0.0.1:6379
  export TAINTGRAPH_SEED="${TAINTGRAPH_SEED:-1}" TAINTGRAPH_CONCURRENCY="${TAINTGRAPH_CONCURRENCY:-8}" TAINTGRAPH_HEAVY_FETCHES="${TAINTGRAPH_HEAVY_FETCHES:-2}"
  export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=320}"
fi
exec node --import tsx src/index.ts
