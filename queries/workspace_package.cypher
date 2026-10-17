// Every project in the workspace whose latest scan installs a package (any version, or one version), with who
// published that version and who maintains the package, so an account can be followed next.
MATCH (p:Project)<-[:OF_PROJECT]-(s:Scan)-[w:SAW]->(v:Version)
WHERE s.id = p.latest_scan AND toLower(v.name) = toLower($name)
WITH p, v, w, $version AS want
WITH p, v, w, CASE WHEN want IS NULL OR v.version = want THEN 1 ELSE 0 END AS hit
WITH p, v, w WHERE hit = 1
OPTIONAL MATCH (pub:Account)-[:PUBLISHED]->(v)
WITH p, v, w, collect(DISTINCT pub.login) AS publishers
OPTIONAL MATCH (v)-[:OF]->(:Package)<-[:MAINTAINS]-(m:Account)
WITH p, v, w, publishers, collect(DISTINCT m.login) AS maintainers
RETURN p.id AS projectId, p.name AS project, p.verdict AS verdict, v.key AS key, v.version AS version, w.dev AS dev,
       publishers, maintainers
ORDER BY project
