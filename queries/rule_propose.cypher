MERGE (r:Rule {id: $id})
ON CREATE SET r.when = $when, r.then = $then, r.status = 'proposed', r.created_at = timestamp()
SET r.confidence = $confidence
WITH r
UNWIND $from AS fid
MATCH (f:Finding {id: fid})
MERGE (r)-[:LEARNED_FROM]->(f)
RETURN DISTINCT r {.id, .when, .then, .status, .confidence} AS rule
