// Each version has one previous release. A rescan replaces an outdated link instead of adding a second one.
UNWIND $rows AS r
MATCH (prev:Version {key: r.prev}), (v:Version {key: r.key})
OPTIONAL MATCH (old:Version)-[e:PRECEDES]->(v)
WITH prev, v, collect(CASE WHEN old.key <> prev.key THEN e END) AS stale
FOREACH (x IN stale | DELETE x)
MERGE (prev)-[:PRECEDES]->(v)
