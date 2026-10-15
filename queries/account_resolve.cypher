// Resolve a login before simulating: only accounts that maintain something in this project count.
MATCH (:Scan {id: $scanId})-[:SAW]->(:Version)-[:OF]->(:Package)<-[:MAINTAINS]-(a:Account)
WHERE toLower(a.login) = toLower($login) OR a.key = $login
RETURN DISTINCT a.key AS key, a.login AS login LIMIT 1
