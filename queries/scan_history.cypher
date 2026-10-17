// The two most recent scans of a project, newest first.
MATCH (s:Scan)-[:OF_PROJECT]->(:Project {id: $projectId})
RETURN s.id AS id, s.at AS at
ORDER BY at DESC
LIMIT 2
