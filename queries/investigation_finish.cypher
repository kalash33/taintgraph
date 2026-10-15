MATCH (i:Investigation {id: $id})
SET i.status = $status, i.answer = $answer, i.outcome = $outcome, i.validated = $validated, i.agent = $agent,
    i.finished_at = timestamp()
WITH i
UNWIND $versionKeys AS k
MATCH (f:Finding {project_id: $projectId})-[:ABOUT]->(:Version {key: k})
MERGE (i)-[:CONCLUDED]->(f)
