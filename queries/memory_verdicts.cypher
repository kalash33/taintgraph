MATCH (f:Finding)-[:ABOUT]->(v:Version)
WHERE f.status IN ['confirmed', 'dismissed', 'accepted']
RETURN f.id AS findingId, v.key AS versionKey, f.signal AS signal, f.status AS verdict,
       coalesce(f.status_note, '') AS note, f.verdict_at AS at
ORDER BY at DESC LIMIT 50
