// Memory recall: earlier human verdicts on the same versions, from any project in the workspace.
MATCH (f:Finding)-[:ABOUT]->(v:Version)
WHERE v.key IN $keys AND f.status IN ['confirmed', 'dismissed', 'accepted']
RETURN v.key AS version, f.signal AS signal, f.status AS verdict, f.status_note AS note, f.id AS id,
       f.verdict_at AS at, f.project_id AS projectId
