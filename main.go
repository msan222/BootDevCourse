package main

import (
	"log"
	"net/http"
)

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8 ")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	mux := http.NewServeMux()

	mux.Handle("/app/", http.StripPrefix("/app", http.FileServer(http.Dir("."))))
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("assets"))))
	mux.HandleFunc("/healthz", healthzHandler)

	server := &http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	log.Println("Starting server on :8080")
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}

}
