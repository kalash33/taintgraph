MATCH (i:Investigation {id: $id})-[:ABOUT_PROJECT]->(p:Project)
OPTIONAL MATCH (i)-[:HAS_STEP]->(s:Step)
WITH i, p, s ORDER BY s.idx
RETURN i {.id, .question, .status, .agent, .answer, .outcome, .validated, .started_at} AS investigation, p.id AS projectId,
       collect(s {.idx, .tool, .label, .input, .outcome, .summary, .cypher, .evidence, .at}) AS steps
