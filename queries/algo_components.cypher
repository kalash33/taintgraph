// Connected components (WCC) over Account-MAINTAINS-Package: maintainers linked through shared packages, transitively.
// A self-spreading worm can only travel inside one component, so its size is the ceiling on how far it can spread.
CALL algo.WCC({nodeLabels: ['Account', 'Package'], relationshipTypes: ['MAINTAINS']}) YIELD node, componentId
WITH node, componentId WHERE node:Account
MATCH (s:Scan {id: $scanId})
MATCH (s)-[:SAW]->(:Version)-[:OF]->(:Package)<-[:MAINTAINS]-(node)
WITH componentId, collect(DISTINCT node.key) AS accounts
RETURN componentId, size(accounts) AS accounts
ORDER BY accounts DESC
LIMIT 3
