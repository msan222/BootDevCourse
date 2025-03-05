func ValidateJWT 
- This is the definition of a function named ValidateJWT. It takes two parameters:
    - tokenString: A string representing the JWT you want to validate.
    - tokenSecret: A string representing the secret key used to sign the JWT.
It returns 2 things:
    - uuid.UUID: This is the user's ID extracted from the token if the validation is successful.
    - error: If there’s a problem with the token, it returns an error.