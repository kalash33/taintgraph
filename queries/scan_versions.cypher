// Every version one scan saw.
MATCH (:Scan {id: $scanId})-[:SAW]->(v:Version)
RETURN v.key AS key, v.name AS name, v.version AS version
