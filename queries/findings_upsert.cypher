// Human verdicts (confirmed / dismissed / accepted) survive rescans; everything else follows the latest triage.
UNWIND $rows AS r
MATCH (p:Project {id: $projectId}), (v:Version {key: r.version})
MERGE (f:Finding {id: r.id})
ON CREATE SET f.created_at = timestamp()
SET f.signal = r.signal, f.severity = r.severity, f.title = r.title, f.detail = r.detail, f.fix = r.fix,
    f.path = r.path, f.ecosystem = r.ecosystem, f.project_id = $projectId, f.scan_id = $scanId, f.rule_id = r.ruleId
SET f.status_note = CASE WHEN f.status IN ['confirmed', 'dismissed', 'accepted'] THEN f.status_note ELSE r.note END,
    f.status = CASE WHEN f.status IN ['confirmed', 'dismissed', 'accepted'] THEN f.status ELSE r.status END
MERGE (f)-[:ABOUT]->(v)
MERGE (f)-[:IN_PROJECT]->(p)
