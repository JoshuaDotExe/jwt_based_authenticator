package auth

import (
	"errors"
	"net/http"
	"strings"

	"jwt_based_authenticator/internal/user"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func NewMiddleware(config MiddlewareConfig) gin.HandlerFunc {
	secret := strings.TrimSpace(config.Secret)
	expectedIssuer := strings.TrimSpace(config.ExpectedIssuer)
	expectedAudience := strings.TrimSpace(config.ExpectedAudience)

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
		parseOptions := []jwt.ParserOption{jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()})}
		if expectedIssuer != "" {
			parseOptions = append(parseOptions, jwt.WithIssuer(expectedIssuer))
		}
		if expectedAudience != "" {
			parseOptions = append(parseOptions, jwt.WithAudience(expectedAudience))
		}

		parsedToken, err := jwt.ParseWithClaims(rawToken, claims, func(token *jwt.Token) (any, error) {
			if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(secret), nil
		}, parseOptions...)
		if err != nil || !parsedToken.Valid || strings.TrimSpace(claims.Subject) == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
			return
		}

		c.Set(user.AuthenticatedUserIDKey, claims.Subject)
		c.Next()
	}
}
