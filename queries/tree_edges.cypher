// Only edges this project's own lockfile declares.
MATCH (s:Scan {id: $scanId})
WITH s, $projectId AS pid
MATCH (s)-[:SAW]->(a:Version)-[e:DEPENDS_ON]->(b:Version)<-[:SAW]-(s)
WITH a, b, e, pid WHERE pid IN e.projects
RETURN a.key AS from, b.key AS to
