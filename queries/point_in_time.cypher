// Were we exposed on a date, and was the advisory public yet? (No publish date means unknown, not "known".)
MATCH (s:Scan)-[:OF_PROJECT]->(:Project {id: $projectId})
WHERE s.at <= $t
WITH s ORDER BY s.at DESC LIMIT 1
MATCH (s)-[:SAW]->(v:Version)<-[:AFFECTS]-(a:Advisory)
RETURN s.id AS scan, a.id AS advisory, v.key AS version, a.published AS published,
       CASE WHEN a.published IS NULL OR a.published = '' THEN null ELSE a.published <= $iso END AS knownAtTheTime
