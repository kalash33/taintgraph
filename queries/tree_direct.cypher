MATCH (:Project {id: $projectId})-[e:DEPENDS_ON]->(v:Version)
RETURN v.key AS key, e.dev AS dev
