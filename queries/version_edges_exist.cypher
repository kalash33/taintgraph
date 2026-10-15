// Whether any version depends on another: PageRank fails on a graph with no such edges (LAGr_PageRank -1000).
MATCH (:Version)-[:DEPENDS_ON]->(:Version)
RETURN count(*) > 0 AS any
LIMIT 1
