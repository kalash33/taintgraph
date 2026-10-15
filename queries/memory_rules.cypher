MATCH (r:Rule)
OPTIONAL MATCH (r)-[:LEARNED_FROM]->(f:Finding)
RETURN r {.id, .when, .then, .status, .confidence} AS rule, collect(f.id) AS learnedFrom
