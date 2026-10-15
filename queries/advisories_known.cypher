// Advisories already linked to each observed version, so the Sentinel can tell new ones apart.
MATCH (a:Advisory)-[:AFFECTS]->(v:Version)
RETURN v.key AS key, collect(a.id) AS ids
