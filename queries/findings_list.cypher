MATCH (f:Finding {project_id: $projectId, scan_id: $scanId})-[:ABOUT]->(v:Version)
OPTIONAL MATCH (f)-[:EVIDENCE]->(a:Advisory)
RETURN f {.id, .signal, .severity, .title, .detail, .fix, .path, .status, .status_note, .ecosystem} AS finding,
       v.key AS versionKey, v.name AS name, v.version AS version, collect(a {.id, .summary, .url}) AS advisories
