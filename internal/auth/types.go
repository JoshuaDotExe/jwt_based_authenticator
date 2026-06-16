package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	Secret          string
	Issuer          string
	DefaultAudience string
	AccessTokenTTL  time.Duration
	IDTokenTTL      time.Duration
}

type TokenInput struct {
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

type AuthenticatedUser struct {
	ID           string
	FirstName    string
	LastName     string
	Email        string
	PasswordHash string
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type MiddlewareConfig struct {
	Secret           string
	ExpectedIssuer   string
	ExpectedAudience string
}
