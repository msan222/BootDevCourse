jwt.ParseWithClaims: tries to parse tokenString and check if it's a valid JWT. It also extracts the claims (data) inside the token.

&jwt.RegisteredClaims{} - This is where the claims will be stored once the token is parsed. 

func(token *jwt.Token) (interface{}, error)
- function that returns the secret key that is used to sign the token. 
- interface{} means return any type. In this case it will be the secret key. 