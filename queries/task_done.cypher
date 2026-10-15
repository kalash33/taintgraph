MATCH (t:Task {id: $id})
SET t.status = $status, t.done_at = timestamp(), t.result = $result
