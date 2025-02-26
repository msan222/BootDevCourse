http.HandlerFunc()
- A type that adapts a function with the signature below and turns it into an http.Handler type:
func(w http.ResponseWriter, w *http.Request)
- it takes a function as an argument and returns a type that satisfies the http.Handler interface.
- **It allows you to write inline anonymous functions as HTTP handlers. 
- Here it's the middleware logic for each request

func(w http.ResponseWriter, r *http.Request)
- This is an anonymous function.
- w is the response writer. It is used to write the HTTP response back to the client. 
- r is the request that contains the info about the incoming HTTP request (GET, Headers, url, etc)

