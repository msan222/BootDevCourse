-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at, revoked_at)
VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    NULL               
)
RETURNING token;

-- name: GetRefreshToken :one
SELECT token, created_at, updated_at, user_id, expires_at, revoked_at
FROM refresh_tokens
WHERE token = $1 AND revoked_at IS NULL;

-- name: GetUserFromRefreshToken :one
SELECT user_id
FROM refresh_tokens
JOIN users ON refresh_tokens.user_id = users.id
WHERE refresh_tokens.token = $1
AND refresh_tokens.expires_at > NOW()
AND (refresh_tokens.revoked_at IS NULL OR refresh_tokens.revoked_at > NOW());

-- name: CheckRefreshTokenExists :one
SELECT EXISTS (
    SELECT 1 FROM refresh_tokens WHERE token = $1
) AS exists;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = $1, updated_at = CURRENT_TIMESTAMP
WHERE token = $2; 


