// Without dependency edges every version weighs the same.
MATCH (v:Version) WHERE v.rank IS NULL
SET v.rank = 1.0
