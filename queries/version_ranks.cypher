MATCH (:Scan {id: $scanId})-[:SAW]->(v:Version)
RETURN v.key AS key, coalesce(v.rank, 0.0) AS rank
