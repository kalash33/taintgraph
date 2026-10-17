// Every project in the workspace that an account can publish into (it maintains a package the latest scan installs).
MATCH (a:Account)
WHERE toLower(a.login) = toLower($login) OR a.key = $login
MATCH (a)-[:MAINTAINS]->(:Package)<-[:OF]-(v:Version)<-[:SAW]-(s:Scan)-[:OF_PROJECT]->(p:Project)
WHERE s.id = p.latest_scan
RETURN a.login AS login, a.key AS accountKey, p.id AS projectId, p.name AS project, count(DISTINCT v) AS versions, collect(DISTINCT v.name)[0..6] AS packages
ORDER BY versions DESC
