// Everything about one installed version: advisories, publishers, maintainers, previous release.
MATCH (v:Version {key: $key})
OPTIONAL MATCH (:Scan {id: $scanId})-[w:SAW]->(v)
OPTIONAL MATCH (a:Advisory)-[:AFFECTS]->(v)
OPTIONAL MATCH (pub:Account)-[:PUBLISHED]->(v)
OPTIONAL MATCH (v)-[:OF]->(pkg:Package)
OPTIONAL MATCH (pkg)<-[:MAINTAINS]-(m:Account)
OPTIONAL MATCH (prev:Version)-[:PRECEDES]->(v)
WITH v, w, pkg, collect(DISTINCT a {.id, .kind, .summary, .url}) AS advisories,
     collect(DISTINCT pub.login) AS publishers, collect(DISTINCT m.login) AS maintainers, collect(DISTINCT prev.key) AS previous
RETURN v {.key, .name, .version, .ecosystem, .published_at, .has_install_script, .install_scripts, .has_provenance, .removed, .rank} AS version,
       w.dev AS dev, pkg.dependents AS dependents, pkg.downloads AS downloads, previous[0] AS previous,
       advisories, publishers, maintainers
