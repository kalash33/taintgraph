MATCH (:Scan {id: $scanId})-[w:SAW]->(v:Version)
RETURN v.key AS key, v.name AS name, v.version AS version, w.dev AS dev
