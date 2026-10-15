// Atomic claim: FalkorDB applies writes to one graph one query at a time, so two workers can't take the same task.
MATCH (t:Task {status: 'open', for_agent: $agent})
WITH t ORDER BY t.created_at LIMIT 1
SET t.status = 'claimed', t.claimed_by = $worker, t.claimed_at = timestamp()
WITH t
MATCH (t)-[:FOR_PROJECT]->(p:Project)
RETURN t {.id, .type, .payload} AS task, p.id AS projectId
