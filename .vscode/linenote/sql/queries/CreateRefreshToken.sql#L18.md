1. Finds a user by joining the users and refresh_tokens tables.
2. Ensures the refresh token is not expired (expires_at > NOW()).
3. Ensures the token is not revoked (revoked_at IS NULL OR revoked_at > NOW()).
4. Returns the id and email of the user associated with the token.
