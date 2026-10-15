UNWIND $rows AS r
MERGE (a:Account {key: r.key})
SET a.login = r.login, a.kind = r.kind
WITH a, r
MATCH (v:Version {key: r.version})
MERGE (a)-[:PUBLISHED]->(v)
