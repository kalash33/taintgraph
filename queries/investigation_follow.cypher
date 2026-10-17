// A follow-up question: link it to the investigation it continues (only within the same project).
MATCH (i:Investigation {id: $id})-[:ABOUT_PROJECT]->(p:Project)
MATCH (prev:Investigation {id: $prev})-[:ABOUT_PROJECT]->(p)
MERGE (i)-[:FOLLOWS]->(prev)
RETURN prev.id AS prev
