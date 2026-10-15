MATCH (p:Project {id: $projectId})
RETURN p.report AS markdown
