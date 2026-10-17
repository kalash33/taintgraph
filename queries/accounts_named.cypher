// Which of these words are maintainer logins anywhere in the workspace (for questions that name an account).
MATCH (a:Account)
WHERE toLower(a.login) IN $words
RETURN DISTINCT a.login AS login
