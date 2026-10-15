// The AI tools' own supply chain: each MCP server, the package it runs, and advisories anywhere under it
// (through this project's own edges; filtered with CASE because WHERE on this OPTIONAL MATCH drops rows in FalkorDB 6).
MATCH (s:McpServer)-[:DECLARED_IN]->(:Project {id: $projectId})
WITH s, $projectId AS pid
OPTIONAL MATCH (s)-[:RUNS]->(v:Version)
OPTIONAL MATCH path = (v)-[:DEPENDS_ON*0..6]->(:Version)<-[:AFFECTS]-(a:Advisory)
WITH s, v, CASE WHEN path IS NOT NULL AND all(r IN relationships(path) WHERE type(r) <> 'DEPENDS_ON' OR pid IN r.projects) THEN a.id END AS adv
RETURN s.key AS key, s.name AS name, s.client AS client, s.command AS command, s.pinned AS pinned,
       v.key AS packageKey, collect(DISTINCT adv) AS advisories
