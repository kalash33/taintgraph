// Episodic recall: what earlier investigations of this project asked and concluded.
MATCH (i:Investigation {status: 'done'})-[:ABOUT_PROJECT]->(:Project {id: $projectId})
OPTIONAL MATCH (i)-[:CONCLUDED]->(f:Finding)
WITH i, collect(DISTINCT f.title) AS concluded
RETURN i.id AS id, i.question AS question, i.started_at AS at, concluded
ORDER BY at DESC LIMIT 3
