MATCH (p:Project {id: $projectId})
SET p.verdict = $verdict
