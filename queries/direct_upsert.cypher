UNWIND $rows AS r
MATCH (p:Project {id: $projectId}), (v:Version {key: r.key})
MERGE (p)-[e:DEPENDS_ON]->(v)
SET e.dev = r.dev
