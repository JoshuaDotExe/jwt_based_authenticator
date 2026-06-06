package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/argon2"
	"jwt_based_authenticator/internal/user"
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

func authMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authorizationHeader := strings.TrimSpace(c.GetHeader("Authorization"))
		if !strings.HasPrefix(authorizationHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]string{"error": "missing or invalid authorization header"})
			return
		}

		rawToken := strings.TrimSpace(strings.TrimPrefix(authorizationHeader, "Bearer "))
		if rawToken == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
			return
		}

		claims := &jwt.RegisteredClaims{}
		parsedToken, err := jwt.ParseWithClaims(rawToken, claims, func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(jwtSecret), nil
		})
		if err != nil || !parsedToken.Valid || strings.TrimSpace(claims.Subject) == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
			return
		}

		c.Set(user.AuthenticatedUserIDKey, claims.Subject)
		c.Next()
	}
}

func verifyArgon2idPassword(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("invalid argon2id hash format")
	}

	versionPart := strings.TrimPrefix(parts[2], "v=")
	version, err := strconv.Atoi(versionPart)
	if err != nil || version != argon2.Version {
		return false, errors.New("unsupported argon2 version")
	}

	var memory uint32
	var timeCost uint32
	var threads uint8
	paramParts := strings.Split(parts[3], ",")
	if len(paramParts) != 3 {
		return false, errors.New("invalid argon2id parameters")
	}

	memoryValue, err := strconv.ParseUint(strings.TrimPrefix(paramParts[0], "m="), 10, 32)
	if err != nil {
		return false, errors.New("invalid argon2id memory parameter")
	}
	timeCostValue, err := strconv.ParseUint(strings.TrimPrefix(paramParts[1], "t="), 10, 32)
	if err != nil {
		return false, errors.New("invalid argon2id time parameter")
	}
	threadsValue, err := strconv.ParseUint(strings.TrimPrefix(paramParts[2], "p="), 10, 8)
	if err != nil {
		return false, errors.New("invalid argon2id threads parameter")
	}

	memory = uint32(memoryValue)
	timeCost = uint32(timeCostValue)
	threads = uint8(threadsValue)

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, errors.New("invalid argon2id salt")
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, errors.New("invalid argon2id hash")
	}

	computedHash := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, uint32(len(hash)))
	if subtle.ConstantTimeCompare(computedHash, hash) != 1 {
		return false, nil
	}

	return true, nil
}

func authenticateUser(ctx context.Context, db *sql.DB, username, password string) (authenticatedUser, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return authenticatedUser{}, errors.New("username and password are required")
	}

	var user authenticatedUser

	err := db.QueryRowContext(
		ctx,
		"SELECT u.id::text, u.first_name, u.last_name, u.email, c.password_hash FROM users u JOIN user_credentials c ON c.user_id = u.id WHERE u.username = $1",
		username,
	).Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.PasswordHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return authenticatedUser{}, errors.New("invalid credentials")
		}
		return authenticatedUser{}, err
	}

	isValidPassword, err := verifyArgon2idPassword(password, user.PasswordHash)
	if err != nil || !isValidPassword {
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
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

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

	userHandler := user.NewHandler(user.NewPostgresService(db))

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, healthResponse{
			Status:    "ok",
			Service:   "jwt-api",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
	})

	router.POST("/token", func(c *gin.Context) {
		var req createTokenRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}

		user, err := authenticateUser(c.Request.Context(), db, req.Username, req.Password)
		if err != nil {
			if err.Error() == "invalid credentials" {
				c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
				return
			}

			if err.Error() == "username and password are required" {
				c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}

			log.Printf("authentication error: %v", err)
			c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal server error"})
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
			c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create tokens"})
			return
		}

		c.JSON(http.StatusCreated, resp)
	})

	router.POST("/user/create", userHandler.PostUser)

	protected := router.Group("")
	protected.Use(authMiddleware(jwtSecret))
	protected.GET("/me", userHandler.GetMe)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("api listening on :%s", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
