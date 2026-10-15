UNWIND $rows AS r
MATCH (f:Finding {id: r.id}), (a:Advisory {id: r.advisory})
MERGE (f)-[:EVIDENCE]->(a)
