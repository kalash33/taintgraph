// Procedural memory: how many findings with this signal got this verdict?
MATCH (f:Finding {status: $verdict, signal: $signal})
RETURN collect(f.id) AS ids
