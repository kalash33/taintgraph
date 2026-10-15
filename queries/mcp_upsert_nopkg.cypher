UNWIND $rows AS r
MATCH (p:Project {id: $projectId})
MERGE (s:McpServer {key: r.key})
SET s.name = r.name, s.client = r.client, s.command = r.command, s.pinned = r.pinned
MERGE (s)-[:DECLARED_IN]->(p)
