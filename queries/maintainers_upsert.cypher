UNWIND $rows AS r
MERGE (a:Account {key: r.key})
SET a.login = r.login, a.kind = r.kind
WITH a, r
MATCH (p:Package {key: r.pkg})
MERGE (a)-[:MAINTAINS]->(p)
