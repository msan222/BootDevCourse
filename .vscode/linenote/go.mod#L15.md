- create a new HTTP request multiplexer (or ServerMux)
- a multiplexer is used to route incoming HTTP requests to the correct handler based on the request's URL

Breakdown for Dummies

- mux is the variable that will hold the instance of the HTTP multiplexer (gate/controller). It will route HTTP requests to different handlers based on the request's URL
:= means initialize without a type

- http.NewServerMux() is a function provided by net/http that creates a new instance of ServerMux
    - doesn't take any arguments 
    - after called this function you'll usually used the returned ServerMux instance (like mux) to register URL patterns/handlers

- ServerMux is a type in Go that is a router to listen and route HTTP requests based on their URL
- **ServerMux keeps a map of URL patterns and the handlers for those URLs

ServerMux in Depth
- ServerMux instance allows you to assign handlers to specific URL paths. 
i.e if you have a url /api/ you can tell the ServerMux to route all requests starting with /api/ to a specific handler function. If there is no matching handler found for a url it returns a 404 error 