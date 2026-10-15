// Independent counts in subqueries, so versions x accounts x advisories never multiply.
MATCH (s:Scan {id: $scanId})
CALL { WITH s MATCH (s)-[:SAW]->(v:Version) RETURN count(v) AS packages }
CALL { WITH s MATCH (s)-[:SAW]->(:Version)-[:OF]->(:Package)<-[:MAINTAINS]-(a:Account) RETURN count(DISTINCT a) AS accounts }
CALL { WITH s MATCH (s)-[:SAW]->(:Version)<-[:AFFECTS]-(x:Advisory) RETURN count(DISTINCT x) AS advisories }
RETURN packages, accounts, advisories
