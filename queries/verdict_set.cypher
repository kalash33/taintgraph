MATCH (f:Finding {id: $id})-[:ABOUT]->(v:Version)
SET f.status = $verdict, f.status_note = $note, f.verdict_at = timestamp()
RETURN f.signal AS signal, v.key AS version, f.project_id AS projectId
