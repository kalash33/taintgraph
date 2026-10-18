#!/bin/sh
# Start FalkorDB on localhost only, wait until it answers, then run Taintgraph in the foreground.
set -e
mkdir -p "${FALKORDB_DATA_PATH:-/var/lib/falkordb/data}"
redis-server --bind 127.0.0.1 --port 6379 --protected-mode yes --save "" --appendonly no \
  --dir "${FALKORDB_DATA_PATH:-/var/lib/falkordb/data}" \
  --loadmodule "${FALKORDB_BIN_PATH:-/var/lib/falkordb/bin}/falkordb.so" ${FALKORDB_ARGS} &
for i in $(seq 1 50); do
  redis-cli -h 127.0.0.1 ping >/dev/null 2>&1 && break
  sleep 0.2
done
exec node --import tsx src/index.ts
