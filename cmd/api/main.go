package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

type healthResponse struct {
	Status    string `json:"status"`
	Service   string `json:"service"`
	Timestamp string `json:"timestamp"`
}

type createTokenRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Aud      string `json:"aud"`
}

type accessTokenInput struct {
	Sub       string
	Aud       string
	FirstName string
	LastName  string
	Email     string
}

type accessTokenClaims struct {
	jwt.RegisteredClaims
}

type idTokenClaims struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	jwt.RegisteredClaims
}

type authenticatedUser struct {
	ID           string
	FirstName    string
	LastName     string
	Email        string
	PasswordHash string
}

type createTokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func authenticateUser(ctx context.Context, db *sql.DB, username, password string) (authenticatedUser, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return authenticatedUser{}, errors.New("username and password are required")
	}

	var user authenticatedUser

	err := db.QueryRowContext(
		ctx,
		"SELECT id::text, first_name, last_name, email, password_hash FROM users WHERE username = $1",
		username,
	).Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.PasswordHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return authenticatedUser{}, errors.New("invalid credentials")
		}
		return authenticatedUser{}, err
	}

	computedHash := fmt.Sprintf("%x", sha256.Sum256([]byte(password)))
	if subtle.ConstantTimeCompare([]byte(computedHash), []byte(strings.ToLower(user.PasswordHash))) != 1 {
		return authenticatedUser{}, errors.New("invalid credentials")
	}

	return user, nil
}

func createAccessToken(secret string, req accessTokenInput) (string, error) {
	if req.Aud == "" {
		req.Aud = "api.local"
	}

	now := time.Now().UTC()

	claims := accessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "auth.local",
			Subject:   req.Sub,
			Audience:  jwt.ClaimStrings{req.Aud},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			ID:        uuid.NewString(),
		},
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
}

func createIDToken(secret string, req accessTokenInput) (string, error) {
	if req.Aud == "" {
		req.Aud = "api.local"
	}

	now := time.Now().UTC()

	claims := idTokenClaims{
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Email:     req.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "auth.local",
			Subject:   req.Sub,
			Audience:  jwt.ClaimStrings{req.Aud},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			ID:        uuid.NewString(),
		},
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
}

func createRefreshToken() (string, error) {
	randomBytes := make([]byte, 48)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

func createTokens(secret string, req accessTokenInput) (createTokenResponse, error) {
	if req.Sub == "" {
		return createTokenResponse{}, errors.New("sub is required")
	}

	accessToken, err := createAccessToken(secret, req)
	if err != nil {
		return createTokenResponse{}, err
	}

	idToken, err := createIDToken(secret, req)
	if err != nil {
		return createTokenResponse{}, err
	}

	refreshToken, err := createRefreshToken()
	if err != nil {
		return createTokenResponse{}, err
	}

	return createTokenResponse{
		AccessToken:  accessToken,
		IDToken:      idToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    900,
	}, nil
}

func main() {
	mux := http.NewServeMux()
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatalf("error: DATABASE_URL environment variable not set")
	}

	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		log.Fatalf("error: failed to open database: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		log.Fatalf("error: failed to connect to database: %v", err)
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatalf("error: JWT_SECRET environment variable not set")
	}

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		writeJSON(w, http.StatusOK, healthResponse{
			Status:    "ok",
			Service:   "jwt-api",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req createTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}

		user, err := authenticateUser(r.Context(), db, req.Username, req.Password)
		if err != nil {
			if err.Error() == "invalid credentials" {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
				return
			}

			if err.Error() == "username and password are required" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}

			log.Printf("authentication error: %v", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			return
		}

		resp, err := createTokens(jwtSecret, accessTokenInput{
			Sub:       user.ID,
			Aud:       req.Aud,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Email:     user.Email,
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create tokens"})
			return
		}

		writeJSON(w, http.StatusCreated, resp)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("api listening on :%s", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
