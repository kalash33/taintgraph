// Resolve a package name to the versions this project actually installs (case-insensitive).
MATCH (:Scan {id: $scanId})-[:SAW]->(v:Version)
WHERE toLower(v.name) = toLower($name)
RETURN v.key AS key, v.version AS version
