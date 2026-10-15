// Before a rescan the project gives up every dependency edge it declared; the scan re-claims the ones still true.
MATCH (:Version)-[e:DEPENDS_ON]->(:Version)
WHERE $projectId IN e.projects
SET e.projects = [x IN e.projects WHERE x <> $projectId]
