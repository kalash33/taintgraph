// Versions seen in a lockfile get their derived flags overwritten; "previous release" rows only add history.
UNWIND $rows AS r
MERGE (v:Version {key: r.key})
SET v += r.props
SET v.script_flags = CASE WHEN r.observed THEN r.flags ELSE v.script_flags END,
    v.removed = CASE WHEN r.observed THEN r.removed ELSE v.removed END
WITH v, r
MATCH (p:Package {key: r.pkg})
MERGE (v)-[:OF]->(p)
