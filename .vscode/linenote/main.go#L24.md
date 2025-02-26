next.ServeHTTP(w,r)
- This invokes the ServeHTTP method of the handler next.

next
- This is the handler that was passed to the to the middleware. 

ServeHTTP(w, r)
- this processes and HTTP request and writes the response back to the client. 

Summary:

This function middlewareMetricsInc is a middleware function that wraps around the existing HTTP handler next.

It increments the fileserverHits counter each time it's called then passes the request off to the next handler so it continues processing like usual.

http.HandlerFunc creates a new handler that does this behavior of passing the request on, and the middleware is used to wrap an actual handler (also like http.FileServer)