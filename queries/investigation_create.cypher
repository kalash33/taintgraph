MATCH (p:Project {id: $projectId})
CREATE (i:Investigation {id: $id, question: $question, status: 'running', agent: $agent, started_at: timestamp()})
CREATE (i)-[:ABOUT_PROJECT]->(p)
