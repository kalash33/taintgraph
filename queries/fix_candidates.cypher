// For each flagged version: the fixed versions its advisories name, its previous release on the same line, and the
// popular package it imitates if it is a typosquat. The fix plan picks a safe target from these.
// Aggregate in WITH before projecting: returning many columns next to count(DISTINCT …) crashes FalkorDB 6.x.
MATCH (v:Version) WHERE v.key IN $keys
OPTIONAL MATCH (a:Advisory)-[e:AFFECTS]->(v)
WITH v, collect(DISTINCT e.fixed) AS fixed, collect(DISTINCT a.kind) AS kinds
OPTIONAL MATCH (v)-[:OF]->(pk:Package)
OPTIONAL MATCH (p:Version)-[:PRECEDES]->(v)
WITH v, fixed, kinds, pk, p
RETURN v.key AS key, v.name AS name, v.version AS version, v.ecosystem AS ecosystem, v.published_at AS publishedAt, fixed, kinds,
       pk.typosquat_of AS typosquatOf, p.version AS prev, p.removed AS prevRemoved
