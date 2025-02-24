Registers a handler for the root path. 

HandleFunc takes two arguments:
- pattern "/", or the URL pattern to match 
- handler (and inline anonymous function) - this function handles the HTTP request when the URL matches the pattern. In this case it is an unnamed function

"/" pattern
- represents the root URL (http://localhost:8080/) if the server is running locally on port 8080. Whenever a request is made to the site this handler will be triggered. 
- if you were to register a different handler with a different pattern 
"/about/" it would match requests to http://localhost:8080/about instead

func(w http.ReponseWriter). req *http.Request{} (Inline anonymous function)
- anonymous functions defined without a name. often used for one-off handlers or callbacks where we want to handle a specific URL pattern. 
- w http.ReponseWriter is the first parameter. It is used to write a response back to the client. 
    - it provides methods for setting response status code, headers, body, etc
        - i.e you could call w.Write([]byte("Hello World")) to send Hello World as reponse body. 
- req *http.Request is the second parameter that provides access to the incoming HTTP request. 
    - contains info like method (GET, POST, etc), URL, headers, body
    - Can access any data sent in request. i.e. req.URL.PATH gives you the requested URL path.

***The Function Body*** 
- the body of this function is how you handle the request. 