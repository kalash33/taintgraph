// One wave of a Shai-Hulud style worm: hijacked accounts publish poisoned versions of everything they maintain;
// maintainers of packages that depend on a poisoned version run it in dev or CI and lose their tokens too.
// FalkorDB 6 quirks handled here: the Scan is bound once, and the per-project edge filter is a CASE after the
// OPTIONAL MATCH (a WHERE there, after UNWIND, drops every row).
MATCH (s:Scan {id: $scanId})
MATCH (s)-[:SAW]->(v:Version)-[:OF]->(:Package)<-[:MAINTAINS]-(a:Account)
WHERE a.key IN $compromised
WITH s, $projectId AS pid, collect(DISTINCT v) AS infected
UNWIND infected AS iv
OPTIONAL MATCH (s)-[:SAW]->(dep:Version)-[e:DEPENDS_ON]->(iv)
WITH infected, CASE WHEN e IS NOT NULL AND pid IN e.projects THEN dep END AS d
OPTIONAL MATCH (d)-[:OF]->(:Package)<-[:MAINTAINS]-(nxt:Account)
WITH infected, collect(DISTINCT nxt.key) AS nxtKeys
RETURN [x IN infected | x.key] AS poisoned, [k IN nxtKeys WHERE NOT k IN $compromised] AS nextWave
