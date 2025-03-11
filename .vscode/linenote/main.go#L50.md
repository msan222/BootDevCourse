tokenData.RevokedAt.Valid: 
- This checks if the RevokedAt field contains a valid time value (i.e., it is not NULL).

tokenData.RevokedAt.Time != (time.Time{}):
 - This checks if the RevokedAt field is not the zero value of time.Time, which represents an invalid or empty time.

 tokenData.ExpiresAt.Before(time.Now()): 
 - This checks if the token's expiration time (ExpiresAt) has passed.