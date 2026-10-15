// Version -> version edges are shared in the workspace but remember which projects' lockfiles declare them,
// so one project's routes never run through another project's resolution.
UNWIND $rows AS r
MATCH (a:Version {key: r.from}), (b:Version {key: r.to})
MERGE (a)-[e:DEPENDS_ON]->(b)
SET e.projects = CASE
  WHEN e.projects IS NULL THEN [$projectId]
  WHEN $projectId IN e.projects THEN e.projects
  ELSE e.projects + $projectId END
