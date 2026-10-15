// PageRank over the dependency graph: heavily depended-on versions score highest.
CALL algo.pageRank('Version', 'DEPENDS_ON') YIELD node, score
SET node.rank = score
