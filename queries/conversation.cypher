// The conversation so far: the investigation being continued and up to three before it, oldest first.
MATCH (last:Investigation {id: $prev})-[:FOLLOWS*0..3]->(x:Investigation)
WHERE x.status = 'done'
RETURN DISTINCT x.id AS id, x.question AS question, x.answer AS answer, x.started_at AS at
ORDER BY at
