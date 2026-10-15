UNWIND $rows AS r
MATCH (prev:Version {key: r.prev}), (v:Version {key: r.key})
MERGE (prev)-[:PRECEDES]->(v)
