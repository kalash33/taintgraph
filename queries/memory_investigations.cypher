MATCH (i:Investigation)-[:ABOUT_PROJECT]->(p:Project)
RETURN i.id AS id, i.question AS question, p.id AS projectId, p.name AS projectName, i.started_at AS startedAt, i.agent AS agent
ORDER BY startedAt DESC LIMIT 30
