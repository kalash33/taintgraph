MATCH (i:Investigation {id: $investigationId})
CREATE (s:Step {idx: $idx, tool: $tool, label: $label, input: $input, outcome: $outcome, summary: $summary,
                cypher: $queryText, evidence: $evidence, at: timestamp()})
CREATE (i)-[:HAS_STEP]->(s)
WITH i, s
OPTIONAL MATCH (i)-[:HAS_STEP]->(prev:Step)
WITH s, CASE WHEN prev.idx = $idx - 1 THEN prev END AS p
FOREACH (_ IN CASE WHEN p IS NULL THEN [] ELSE [1] END | CREATE (p)-[:NEXT]->(s))
