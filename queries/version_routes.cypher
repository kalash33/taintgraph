// Every shortest route from the project to a version, through this project's own edges only.
MATCH (p:Project {id: $projectId}), (v:Version {key: $key})
WITH p, v, $projectId AS pid
MATCH route = allShortestPaths((p)-[:DEPENDS_ON*]->(v))
WITH route, pid WHERE all(r IN relationships(route) WHERE r.projects IS NULL OR pid IN r.projects)
RETURN [n IN nodes(route) | n.key] AS path
LIMIT 5
