MATCH (r:Rule {status: 'active'})
RETURN r.id AS id, r.when AS when, r.then AS then, r.confidence AS confidence
