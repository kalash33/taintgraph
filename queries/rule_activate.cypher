MATCH (r:Rule {id: $id})
SET r.status = 'active', r.activated_at = timestamp()
RETURN r.id AS id
