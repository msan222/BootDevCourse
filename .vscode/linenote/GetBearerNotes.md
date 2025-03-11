The GetBearerToken function is responsible for extracting a JWT from the HTTP Authorization header of incoming requests. This function will:

Check if the Authorization header exists in the request headers.
Ensure the value starts with Bearer , followed by the token.
Extract and return the actual token string (removing the Bearer prefix and any extra whitespace).
Return an error if the header is missing or malformed.
