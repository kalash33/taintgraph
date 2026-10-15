UNWIND $rows AS r
MERGE (a:Advisory {id: r.id})
SET a.kind = r.kind, a.severity = r.severity, a.summary = r.summary, a.published = r.published, a.url = r.url
WITH a, r
MATCH (v:Version {key: r.version})
MERGE (a)-[e:AFFECTS]->(v)
ON CREATE SET e.first_seen = timestamp()
SET e.explicit = r.explicit, e.fixed = r.fixed
RETURN a.id AS id, v.key AS version, e.first_seen AS firstSeen
