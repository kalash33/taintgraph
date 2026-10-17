// Maintainer teams: community detection (label propagation) over Account-MAINTAINS-Package. Accounts that maintain the
// same packages land in one community; teams often share tokens, CI and habits, so one phished account is a way into
// the whole team. For each team: how much of this project it can publish.
CALL algo.labelPropagation({nodeLabels: ['Account', 'Package'], relationshipTypes: ['MAINTAINS']}) YIELD node, communityId
WITH node, communityId WHERE node:Account
MATCH (s:Scan {id: $scanId})
MATCH (s)-[:SAW]->(v:Version)-[:OF]->(:Package)<-[:MAINTAINS]-(node)
WITH communityId, collect(DISTINCT node.login) AS logins, collect(DISTINCT node.key) AS keys, collect(DISTINCT v) AS vs
WITH communityId, logins, keys, vs, size(vs) AS versions, reduce(w = 0.0, x IN vs | w + coalesce(x.rank, 0.0)) AS weight
RETURN communityId, logins, keys, versions, weight, [x IN vs | x.key] AS versionKeys
ORDER BY versions DESC
LIMIT $limit
