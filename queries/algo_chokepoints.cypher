// Betweenness centrality: the versions that the most dependency paths flow through.
CALL algo.betweenness({nodeLabels: ['Version'], relationshipTypes: ['DEPENDS_ON']}) YIELD node, score
WITH node, score WHERE score > 0
MATCH (s:Scan {id: $scanId})-[:SAW]->(node)
RETURN node.key AS key, score
ORDER BY score DESC LIMIT 10
