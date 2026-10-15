MATCH (p:Project {id: $projectId})
CREATE (t:Task {id: $id, type: $type, for_agent: $forAgent, status: 'open', created_at: timestamp(), payload: $payload, attempts: 0})
CREATE (t)-[:FOR_PROJECT]->(p)
