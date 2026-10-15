MATCH (p:Project {id: $projectId})
OPTIONAL MATCH (p)-[:DEPENDS_ON]->(d:Version)
RETURN p {.id, .key, .name, .kind, .source, .latest_scan, .scanned_at, .verdict} AS project, count(d) AS direct
