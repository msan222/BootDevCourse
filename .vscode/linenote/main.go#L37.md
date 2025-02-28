json.NewDecoder(r.Body).Decoder(&req)

json.NewDecoder(r.Body)
- read information from Body of request r

.Decode(&req)
- take the info you just read and try to fit it into a container called req
- & means put it directly in