Creates a new instance of the http.Server struct, using the & operator to create a pointer to that instance. In Go structs are normally passed as pointers for efficiency. 

http.Server
- this is a struct in the net/http package, which is responsible for managing an HTTP server. It contains configurations and behavior needed for the HTTP server to operate, such as routing, handling requests, and binding to a specific address. 
- when you create the pointer &http.Server you're essentially preparing an HTTP server to handle incoming requests and respond accordingly to the configurations specified. 

Addr
- This field defines the network address on which the server will listen for incoming connections. 
- ":8080" means that the server will listen on port 8080 on all available network interfaces. In this case, it will only listen on localhost:8080, which means only local connections to the server can reach it. 
    - The : part of :8080 tells the server to bind to any available IP address on the machine (instead of just localhost or another specific address). If you were to set it to localhost:8080 then it would only bind to the local network interface. 


Why use a pointer to http.Server?? (&http.Server)
- by using a pointer you're allowing the server to be modified if needed and **when you call methods on this pointer (server.ListenAndServe()), it operate on the actual instance of the http.Server. 
- If you were to use it just http.Server without a pointer you'd just pass around a copy of the server and Go would have to create new copies of the server object each time, which is super inefficient. 