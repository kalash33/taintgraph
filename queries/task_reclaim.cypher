// Tasks held by a worker that died go back to the queue after 10 minutes (3 attempts at most).
MATCH (t:Task {status: 'claimed'})
WHERE t.claimed_at < timestamp() - 600000
SET t.attempts = coalesce(t.attempts, 0) + 1,
    t.status = CASE WHEN coalesce(t.attempts, 0) + 1 >= 3 THEN 'error' ELSE 'open' END
RETURN count(t) AS reclaimed
