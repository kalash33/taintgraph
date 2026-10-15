MATCH (p:Project {id: $projectId})
SET p.report = $markdown, p.report_at = timestamp()
