MATCH (p:Project)<-[:OF_PROJECT]-(s:Scan)-[:SAW]->(:Version {key: $key})
WITH p, s WHERE s.id = p.latest_scan
RETURN DISTINCT p.id AS id, p.name AS name
