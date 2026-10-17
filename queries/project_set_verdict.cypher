// Set the verdict and mark this scan as the project's last fully triaged one (readers use it).
MATCH (p:Project {id: $projectId})
SET p.verdict = $verdict, p.triaged_at = CASE WHEN p.triaged_scan = $scanId THEN p.triaged_at ELSE p.scanned_at END, p.triaged_scan = $scanId
