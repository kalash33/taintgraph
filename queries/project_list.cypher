MATCH (p:Project)
RETURN p {.id, .name, .kind, .source, .scanned_at, .verdict} AS project
ORDER BY p.scanned_at DESC
