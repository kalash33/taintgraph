// One investigation with its steps in order, and the investigation it follows up on (if any).
MATCH (i:Investigation {id: $id})-[:ABOUT_PROJECT]->(p:Project)
OPTIONAL MATCH (i)-[:FOLLOWS]->(f:Investigation)
WITH i, p, f.id AS followsId
OPTIONAL MATCH (i)-[:HAS_STEP]->(s:Step)
WITH i, p, followsId, s ORDER BY s.idx
WITH i, p, followsId, collect(s {.idx, .tool, .label, .input, .outcome, .summary, .cypher, .evidence, .at}) AS steps
RETURN i {.id, .question, .status, .agent, .answer, .outcome, .validated, .started_at} AS investigation, p.id AS projectId, followsId, steps
