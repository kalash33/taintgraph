// MCP servers belong to one project; a rescan replaces them.
MATCH (s:McpServer)-[:DECLARED_IN]->(:Project {id: $projectId})
DELETE s
