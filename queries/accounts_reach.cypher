// Every version in the project each account can publish (maintainer of its package, or publisher of the release),
// weighted by PageRank. Accounts are the attack surface: one hijacked login reaches all of these.
MATCH (s:Scan {id: $scanId})
CALL {
  WITH s
  MATCH (s)-[:SAW]->(v:Version)-[:OF]->(:Package)<-[:MAINTAINS]-(a:Account)
  RETURN a, v
  UNION
  WITH s
  MATCH (s)-[:SAW]->(v:Version)<-[:PUBLISHED]-(a:Account)
  RETURN a, v
}
WITH a, collect(DISTINCT v) AS vs
RETURN a.key AS key, a.login AS login, a.kind AS kind, size(vs) AS versions,
       reduce(w = 0.0, x IN vs | w + coalesce(x.rank, 0.0)) AS weight, [x IN vs | x.key] AS keys
ORDER BY weight DESC, versions DESC LIMIT $limit
