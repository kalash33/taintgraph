// Every version any project in the workspace has seen, for retro-hunting new advisories.
MATCH (:Scan)-[:SAW]->(v:Version)
RETURN DISTINCT v.key AS key, v.name AS name, v.version AS version, v.ecosystem AS ecosystem
