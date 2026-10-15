MATCH (t:Task)-[:FOR_PROJECT]->(p:Project)
RETURN t {.id, .type, .for_agent, .status, .claimed_by, .created_at, .done_at} AS task, p.name AS projectName
ORDER BY t.created_at DESC LIMIT 40
