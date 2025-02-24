This line registers a handlers for /api/ path.

- tells the multiplexer (mux) that when an HTTP request comes in with a URL starting with /api/, the request should be passed to an instance of apiHandler{}
- apiHandler{} is an empty struct, which implements the ServeHTTP method. 