// internal/auth/auth.go

package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	// bcrypt.GenerateFromPassword generates a bcrypt hash of the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	//return hashed password as string
	return string(hashedPassword), nil
}

func CheckPasswordHash(password, hash string) error {
	//bcrypt.CompareHashAndPassword compares the stored has with provided password
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	//create claims
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
		Subject:   userID.String(), //convert user ID to string
	}

	//create new token with HS256 signing method
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	//Sign the token with the secret key
	signedToken, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	//parse token and validate signatures and claims
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		//Ensure correct signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(tokenSecret), nil
	})
	if err != nil {
		return uuid.Nil, err
	}

	//check if token is valid and extract claims
	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		//convert subject field back to uuid
		userID, err := uuid.Parse(claims.Subject)
		if err != nil {
			return uuid.Nil, err
		}
		return userID, nil
	}
	return uuid.Nil, errors.New("invalid token")
}

// extract a JWT from the HTTP Authorization header of incoming requests
func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header not found")
	}

	//split header into 2 parts "bearer" and token
	parts := strings.Fields(authHeader)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New("invalid authorization format")
	}
	return parts[1], nil
}

func MakeRefreshToken() (string, error) {
	//Generate 32 bytes of random data
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", errors.New("failed to generate random token")
	}

	//Convert random bytes to hex string
	token := hex.EncodeToString(tokenBytes)

	return token, nil
}

func GetAPIKey(headers http.Header) (string, error) {
	//Get the authorization header
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header missing")
	}

	//Expected format: "ApiKey THE_KEY_HERE"
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "ApiKey" {
		return "", errors.New("invalid authorization header format")
	}
	return strings.TrimSpace(parts[1]), nil
}
