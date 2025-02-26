cfg - reciever var name - this is an instance of *apiConfig that the method will use.

*apiConfig - this is a pointer to the Struct apiConfig (that holds the variable of total hits so far).
- The fact that it is a pointer means that it can modify the fields directly, not just a copy. 

middlewareMetricsInc(next http.Handler) http.Handler
- middlewareMetricsInc is the method name. 
- the method takes one argument, next, which is an http.Handler.
- http.Handler (after the method) - the method returns a http.handler

Summary: it takes a pointer to struct *apiConfig and returns a http.Handler next

Notes:
Middleware is a function here that wraps a handler and adds extra behavior (counting) before passing the request on to the next handler. 