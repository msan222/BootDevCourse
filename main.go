package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sync/atomic"
)

var profaneWords = []string{"kerfuffle", "sharbert", "fornax"}

type ChirpRequest struct {
	Body string `json:"body"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type SuccessResponse struct {
	CleanedBody string `json:"cleaned_body"`
}

func cleanChirpText(body string) string {
	//iterate over each profane word and replace with asterisks
	for _, word := range profaneWords {
		//regex to match the words case-insensitive
		re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(word) + `\b`)
		body = re.ReplaceAllString(body, "****")
	}
	return body
}

func validateChirpHandler(w http.ResponseWriter, r *http.Request) {
	//See if it's POST method
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid request method"})
		return
	}
	//Parse the incoming JSON body
	var request ChirpRequest
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&request)

	//Handle JSON parsing errors
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Something went wrong"})
		return
	}

	//validate chirp length
	if len(request.Body) > 140 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Chirp is too long"})
		return
	}

	cleanedBody := cleanChirpText(request.Body)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(SuccessResponse{CleanedBody: cleanedBody})

}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8 ")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//Increment counter by 1
		cfg.fileserverHits.Add(1)
		//Continue with original handler
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	count := cfg.fileserverHits.Load()
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
		<html>
  			<body>
    			<h1>Welcome, Chirpy Admin</h1>
    				<p>Chirpy has been visited %d times!</p>
  			</body>
		</html>`, count)
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg.fileserverHits.Store(0)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "Hits reset to 0")
}

func main() {
	apiCfg := &apiConfig{}
	mux := http.NewServeMux()

	mux.HandleFunc("/api/validate_chirp", validateChirpHandler)
	mux.HandleFunc("/admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("/admin/reset", apiCfg.resetHandler)

	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))

	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("assets"))))

	mux.HandleFunc("/api/healthz", healthzHandler)

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
