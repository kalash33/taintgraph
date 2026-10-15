MATCH (f:Finding {id: $id})
RETURN f.signal AS signal
