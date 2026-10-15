// Shortest route from the project to every version an advisory affects. ownRoute is false when that route uses an
// edge declared only by another project; the caller then uses this project's own tree instead.
MATCH (p:Project {id: $projectId})
MATCH (:Scan {id: $scanId})-[:SAW]->(bad:Version)<-[e:AFFECTS]-(a:Advisory)
WITH p, bad, a, e, $projectId AS pid, shortestPath((p)-[:DEPENDS_ON*]->(bad)) AS route
RETURN a.id AS advisory, a.kind AS kind, a.severity AS severity, a.summary AS summary, a.url AS url,
       e.fixed AS fixed, e.explicit AS explicit, bad.key AS version,
       CASE WHEN route IS NULL THEN [] ELSE [n IN nodes(route) | n.key] END AS path,
       route IS NOT NULL AND all(r IN relationships(route) WHERE r.projects IS NULL OR pid IN r.projects) AS ownRoute
