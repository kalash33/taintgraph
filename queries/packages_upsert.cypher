// Derived flags are always overwritten (null removes them), so better heuristics clear old verdicts on rescan.
UNWIND $rows AS r
MERGE (p:Package {key: r.key})
SET p += r.props, p.typosquat_of = r.typosquatOf
