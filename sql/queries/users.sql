-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),  
    NOW(),             
    NOW(),              
    $1,
    $2                  
)
RETURNING id, email, created_at, updated_at;

-- name: DeleteAllUsers :exec
DELETE FROM users;

-- name: GetUserByEmail :one
SELECT id, email, hashed_password, created_at, updated_at
FROM users
WHERE email = $1
LIMIT 1;

-- name: GetUserByID :one 
SELECT id, email, hashed_password, created_at, updated_at
FROM users
WHERE id = $1
LIMIT 1;

-- name: UpdateUser :one 
UPDATE users
SET email = $2, hashed_password = $3
WHERE id = $1
RETURNING id, email, hashed_password;
                        