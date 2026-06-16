package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Service struct {
	db     *sql.DB
	config Config
}

func NewService(db *sql.DB, config Config) (*Service, error) {
	if db == nil {
		return nil, errors.New("db is required")
	}
	if strings.TrimSpace(config.Secret) == "" {
		return nil, errors.New("auth secret is required")
	}
	if strings.TrimSpace(config.Issuer) == "" {
		config.Issuer = "auth.local"
	}
	if strings.TrimSpace(config.DefaultAudience) == "" {
		config.DefaultAudience = "api.local"
	}
	if config.AccessTokenTTL <= 0 {
		config.AccessTokenTTL = 15 * time.Minute
	}
	if config.IDTokenTTL <= 0 {
		config.IDTokenTTL = 15 * time.Minute
	}

	return &Service{db: db, config: config}, nil
}

func (s *Service) AuthenticateUser(ctx context.Context, username, password string) (AuthenticatedUser, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return AuthenticatedUser{}, ErrMissingCredentials
	}

	var user AuthenticatedUser
	err := s.db.QueryRowContext(
		ctx,
		"SELECT u.id::text, u.first_name, u.last_name, u.email, c.password_hash FROM users u JOIN user_credentials c ON c.user_id = u.id WHERE u.username = $1",
		username,
	).Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.PasswordHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AuthenticatedUser{}, ErrInvalidCredentials
		}
		return AuthenticatedUser{}, err
	}

	isValidPassword, err := verifyArgon2idPassword(password, user.PasswordHash)
	if err != nil || !isValidPassword {
		return AuthenticatedUser{}, ErrInvalidCredentials
	}

	return user, nil
}

func (s *Service) CreateTokens(req TokenInput) (TokenResponse, error) {
	if strings.TrimSpace(req.Sub) == "" {
		return TokenResponse{}, ErrInvalidTokenInput
	}

	accessToken, err := s.createAccessToken(req)
	if err != nil {
		return TokenResponse{}, err
	}

	idToken, err := s.createIDToken(req)
	if err != nil {
		return TokenResponse{}, err
	}

	refreshToken, err := createRefreshToken()
	if err != nil {
		return TokenResponse{}, err
	}

	return TokenResponse{
		AccessToken:  accessToken,
		IDToken:      idToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.config.AccessTokenTTL.Seconds()),
	}, nil
}

func (s *Service) createAccessToken(req TokenInput) (string, error) {
	aud := strings.TrimSpace(req.Aud)
	if aud == "" {
		aud = s.config.DefaultAudience
	}

	now := time.Now().UTC()
	claims := accessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.Issuer,
			Subject:   req.Sub,
			Audience:  jwt.ClaimStrings{aud},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.AccessTokenTTL)),
			ID:        uuid.NewString(),
		},
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(s.config.Secret))
}

func (s *Service) createIDToken(req TokenInput) (string, error) {
	aud := strings.TrimSpace(req.Aud)
	if aud == "" {
		aud = s.config.DefaultAudience
	}

	now := time.Now().UTC()
	claims := idTokenClaims{
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Email:     req.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.config.Issuer,
			Subject:   req.Sub,
			Audience:  jwt.ClaimStrings{aud},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.IDTokenTTL)),
			ID:        uuid.NewString(),
		},
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(s.config.Secret))
}

func createRefreshToken() (string, error) {
	randomBytes := make([]byte, 48)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}
