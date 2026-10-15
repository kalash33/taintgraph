// Create or refresh a project and open a new Scan. Its direct-dependency edges are replaced on every scan.
MERGE (p:Project {id: $id})
SET p.key = $key, p.name = $name, p.kind = $kind, p.source = $source, p.latest_scan = $scanId, p.scanned_at = $at
WITH p
OPTIONAL MATCH (p)-[old:DEPENDS_ON]->()
DELETE old
WITH DISTINCT p
CREATE (:Scan {id: $scanId, at: $at})-[:OF_PROJECT]->(p)
