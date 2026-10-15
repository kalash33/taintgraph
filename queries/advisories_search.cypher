// Full-text search over advisory summaries (RediSearch index).
CALL db.idx.fulltext.queryNodes('Advisory', $text) YIELD node, score
RETURN node.id AS id, node.kind AS kind, node.summary AS summary, node.url AS url, score
ORDER BY score DESC LIMIT 5
