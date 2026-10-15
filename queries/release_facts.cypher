// One row per version: what the previous release looked like, who published each, install scripts, provenance,
// removal from the registry and typosquat names. Feeds the suspicious-release signals.
MATCH (:Scan {id: $scanId})-[:SAW]->(v:Version)
OPTIONAL MATCH (v)-[:OF]->(pkg:Package)
OPTIONAL MATCH (p:Version)-[:PRECEDES]->(v)
WITH v, pkg, p ORDER BY p.published_at DESC
WITH v, pkg, collect(p)[0] AS prev
OPTIONAL MATCH (pub:Account)-[:PUBLISHED]->(v)
WITH v, pkg, prev, collect(DISTINCT pub {.key, .login, .kind}) AS pubs
OPTIONAL MATCH (pp:Account)-[:PUBLISHED]->(prev)
WITH v, pkg, prev, pubs, collect(DISTINCT pp {.key, .login, .kind}) AS prevPubs
RETURN v.key AS key, v.name AS name, v.version AS version, v.ecosystem AS ecosystem,
       v.has_install_script AS script, v.install_scripts AS scripts, v.script_text AS scriptText, v.script_flags AS scriptFlags,
       v.has_provenance AS provenance, v.removed AS removed, v.published_at AS published,
       prev.key AS prevKey, prev.has_install_script AS prevScript, prev.has_provenance AS prevProvenance,
       pubs, prevPubs, pkg.typosquat_of AS typosquatOf, pkg.downloads AS downloads
