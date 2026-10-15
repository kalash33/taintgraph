// SAW holds per-project facts about a version (dev or prod in this lockfile).
UNWIND $rows AS r
MATCH (s:Scan {id: $scanId}), (v:Version {key: r.key})
CREATE (s)-[:SAW {dev: r.dev}]->(v)
