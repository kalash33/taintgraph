MATCH (r:Rule {id: $id})
RETURN r.when AS when, r.status AS status
