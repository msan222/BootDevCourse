method is called ServeHTTP for the type apiHandler. Has the signature expected by the Go HTTP server, which allows apiHandler to handle HTTP requests.

- method ServeHTTP belongs to the type apiHandler.
- When we create an instance of apiHandler, it will have the Server HTTP method available to it. 

- In Go, the HTTP server framework (imported in the net/http package) expects handlers to implement a specific method signature when handling requests. 

i.e. ServeHTTP(w http.ResponseWriter, req *http.Request) for HTTP request handlers

- w of type http.ResponseWriter is used to write the HTTP response back to the client. 
- req  of type *http.Request contains all the details of the incoming HTTP request like URL, HTTP method (GET POST, etc), headers, body, etc

- The expected signature for any handler to process HTTP Go requests is this method called ServeHTTP that takes two arguments http.ResponseWriter and *httpReqest

- in Go's HTTP server model, any type that has method with this specific signature is considered an HTTP handler. That means if you have a type apiHandler and give it this ServerHTTP method with this signature it will treat it as an HTTP handler. 

- "Hey, whenever an HTTP request comes in that should be handled by apiHandler, call this ServeHTTP method."