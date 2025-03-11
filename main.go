package main

import (
	"BootDevCourse/internal/auth"
	"BootDevCourse/internal/database"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type CreateChirpRequest struct {
	Body   string    `json:"body"`
	UserID uuid.UUID `json:"user_id"`
}

type CreateChirpResponse struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Body      string `json:"body"`
	UserID    string `json:"user_id"`
}

func (cfg *apiConfig) refreshHandler(w http.ResponseWriter, r *http.Request) {
	//Extract refresh token from authorization header
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, "Unauthorized: Missing or invalid refresh token", http.StatusBadRequest)
		return
	}

	//Query database for user associated with refresh token
	user1, err := cfg.dbQueries.GetUserFromRefreshToken(r.Context(), refreshToken)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		} else {
			http.Error(w, "Database Error", http.StatusInternalServerError)
		}
		return
	}

	//Issue new access token for 1 hour
	accessToken, err := auth.MakeJWT(user1, cfg.JWTSecret, time.Hour) // 1 hour expiration
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"token": accessToken,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (cfg *apiConfig) revokeHandler(w http.ResponseWriter, r *http.Request) {
	//Get token from authorization header
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, "Invalid or missing refresh token", http.StatusUnauthorized)
		return
	}

	//look up refresh token in database
	tokenExists, err := cfg.dbQueries.CheckRefreshTokenExists(r.Context(), refreshToken)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	//if token doesn't exist respond with 401
	if !tokenExists {
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	//Revoke Token by setting revoked_at to current time
	revokedParams := database.RevokeRefreshTokenParams{
		RevokedAt: sql.NullTime{Time: time.Now(), Valid: true},
		Token:     refreshToken,
	}

}

func (cfg *apiConfig) getChirpByIDHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract the Chirp ID from the path
	chirpID := r.PathValue("chirpID")
	if chirpID == "" {
		http.Error(w, "Missing chirp ID", http.StatusBadRequest)
		return
	}

	//parse the Chirp id into a uuid
	chirpUUID, err := uuid.Parse(chirpID)
	if err != nil {
		http.Error(w, "Invalid chirp ID", http.StatusBadRequest)
		return
	}

	//Query the database for the chirp
	chirp, err := cfg.dbQueries.GetChirpByID(r.Context(), chirpUUID)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Chirp not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	//Format chirp into response struct
	resp := CreateChirpResponse{
		ID:        chirp.ID.String(),
		CreatedAt: chirp.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt: chirp.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		Body:      chirp.Body,
		UserID:    chirp.UserID.String(),
	}

	//Return response as JSON
	w.Header().Set("Content-type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (cfg *apiConfig) getChirpsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	//Call generated query to list chirps
	chirps, err := cfg.dbQueries.GetAllChirps(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//prepare a response slice using the same structure as  CreateChirpResponse
	responses := make([]CreateChirpResponse, len(chirps))
	for i, chirp := range chirps {
		responses[i] = CreateChirpResponse{
			ID:        chirp.ID.String(),
			CreatedAt: chirp.CreatedAt.Format("2006-01-02T15:04:05Z"),
			UpdatedAt: chirp.UpdatedAt.Format("2006-01-02T15:04:05Z"),
			Body:      chirp.Body,
			UserID:    chirp.UserID.String(),
		}
	}

	//Set header and write JSON response w/ 200 status code
	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(responses)
}

func (cfg *apiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		http.Error(w, "Unauthorized: Missing or invalid token", http.StatusUnauthorized)
		return
	}

	userID, err := auth.ValidateJWT(tokenString, cfg.JWTSecret)
	if err != nil {
		http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
		return
	}

	var req CreateChirpRequest
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid Request Body", http.StatusBadRequest)
		return
	}

	if len(req.Body) > 140 {
		http.Error(w, "Chirp is too long", http.StatusBadRequest)
		return
	}

	cleanedBody := cleanChirpText(req.Body)

	chirp, err := cfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:   cleanedBody,
		UserID: userID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := CreateChirpResponse{
		ID:        chirp.ID.String(),
		CreatedAt: chirp.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt: chirp.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		Body:      chirp.Body,
		UserID:    chirp.UserID.String(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

type CreateUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type CreateUserResponse struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Email     string `json:"email"`
}

func (cfg *apiConfig) createUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	//read and decode JSON request body
	var req CreateUserRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid Request Body", http.StatusBadRequest)
		return
	}

	hashedPassword, err2 := auth.HashPassword(req.Password) //Call HashPassword function
	if err2 != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	//Call database to create user with hashed password
	createUserParams := database.CreateUserParams{
		Email:          req.Email,
		HashedPassword: hashedPassword,
	}

	user, err := cfg.dbQueries.CreateUser(r.Context(), createUserParams)
	if err != nil {
		http.Error(w, "Failed to Create User", http.StatusInternalServerError)
		return
	}

	//Build Response
	resp := CreateUserResponse{
		ID:        user.ID.String(),
		CreatedAt: user.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt: user.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		Email:     user.Email,
	}

	//Send the JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func (cfg *apiConfig) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	//read and decode JSON request body
	var req struct {
		Email            string `json:"email"`
		Password         string `json:"password"`
		ExpiresInSeconds int    `json:"expires_in_seconds,omitempty"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	//Query database to find user by email
	user, err := cfg.dbQueries.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Incorrect email or password", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	//Compare the entered password to the one stored in hash
	err = auth.CheckPasswordHash(req.Password, user.HashedPassword)
	if err != nil {
		http.Error(w, "Incorrect email or password", http.StatusUnauthorized)
		return
	}

	//set expiration time
	/*expiresIn := time.Hour
	if req.ExpiresInSeconds > 0 && req.ExpiresInSeconds <= 3600 {
		expiresIn = time.Duration(req.ExpiresInSeconds) * time.Second
	}*/

	// Generate JWT
	token, err := auth.MakeJWT(user.ID, cfg.JWTSecret, time.Hour) // 1 hour expiration
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	//Generate Refresh token
	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	//store refresh token in database with 60-day expiry
	expiresAt := time.Now().Add(60 * 24 * time.Hour) //60 days
	_, err = cfg.dbQueries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     refreshToken,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		UserID:    user.ID,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		http.Error(w, "Failed to store refresh token", http.StatusInternalServerError)
		return
	}

	//if password matches return user data
	/*resp := CreateUserResponse{
		ID:        user.ID.String(),
		CreatedAt: user.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt: user.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		Email:     user.Email,
	}*/

	//Return tokens in response
	resp := struct {
		ID           string `json:"id"`
		CreatedAt    string `json:"created_at"`
		UpdatedAt    string `json:"updated_at"`
		Email        string `json:"email"`
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}{
		ID:           user.ID.String(),
		CreatedAt:    user.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:    user.UpdatedAt.Format("2006-01-02T15:04:05Z"),
		Email:        user.Email,
		Token:        token,
		RefreshToken: refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

var profaneWords = []string{"kerfuffle", "sharbert", "fornax"}

type ChirpRequest struct { // holds body of incoming JSON request
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

/*func validateChirpHandler(w http.ResponseWriter, r *http.Request) {
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

	//String made from calling cleanChirpText to clean the body of the request.
	cleanedBody := cleanChirpText(request.Body)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(SuccessResponse{CleanedBody: cleanedBody})

}*/

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
	dbQueries      *database.Queries
	JWTSecret      string
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

	//check for dev mode
	if os.Getenv("PLATFORM") != "dev" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	//call database to delete all users.
	err := cfg.dbQueries.DeleteAllUsers(r.Context())
	if err != nil {
		http.Error(w, "Failed to delete users", http.StatusInternalServerError)
		return
	}

	cfg.fileserverHits.Store(0)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "All users deleted. Hits reset to 0")
}

func main() {
	//load enviroment variables from .env
	err1 := godotenv.Load()
	if err1 != nil {
		log.Fatal("Error loading .env file")
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is not set in the .env file")
	}

	//get database connection from enviroment variables
	dbURL := os.Getenv("DB_URL")

	//open a connection to the PostgreSQL database
	db, err1 := sql.Open("postgres", dbURL)
	if err1 != nil {
		log.Fatal("Error connecting to the database: ", err1)
	}
	defer db.Close()

	fmt.Println("Successfully connected to the database!")

	//Initialize SQLC queries package
	dbQueries := database.New(db)

	apiCfg := &apiConfig{
		dbQueries: dbQueries,
		JWTSecret: jwtSecret,
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/api/users", apiCfg.createUserHandler)
	mux.HandleFunc("/api/login", apiCfg.loginHandler)
	mux.HandleFunc("/api/refresh", apiCfg.refreshHandler)

	mux.HandleFunc("/api/chirps", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			apiCfg.createChirpHandler(w, r)
		} else if r.Method == http.MethodGet {
			apiCfg.getChirpsHandler(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/chirps/{chirpID}", apiCfg.getChirpByIDHandler)

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
