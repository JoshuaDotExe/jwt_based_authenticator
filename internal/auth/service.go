package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbt "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Service struct {
	ddb              *dynamodb.Client
	usersTable       string
	userUniquesTable string
	config           Config
}

func NewService(ddb *dynamodb.Client, usersTable, userUniquesTable string, config Config) (*Service, error) {
	if ddb == nil {
		return nil, errors.New("dynamodb client is required")
	}
	if strings.TrimSpace(usersTable) == "" {
		return nil, errors.New("users table is required")
	}
	if strings.TrimSpace(userUniquesTable) == "" {
		return nil, errors.New("user uniques table is required")
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

	return &Service{
		ddb:              ddb,
		usersTable:       strings.TrimSpace(usersTable),
		userUniquesTable: strings.TrimSpace(userUniquesTable),
		config:           config,
	}, nil
}

func (s *Service) AuthenticateUser(ctx context.Context, username, password string) (AuthenticatedUser, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return AuthenticatedUser{}, ErrMissingCredentials
	}

	uniqueResp, err := s.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.userUniquesTable,
		Key: map[string]ddbt.AttributeValue{
			"key": &ddbt.AttributeValueMemberS{Value: userUniqueUsernameKey(username)},
		},
		ConsistentRead: boolPtr(true),
	})
	if err != nil {
		return AuthenticatedUser{}, err
	}
	if len(uniqueResp.Item) == 0 {
		return AuthenticatedUser{}, ErrInvalidCredentials
	}

	var uniqueRecord struct {
		UserID string `dynamodbav:"user_id"`
	}
	if err := attributevalue.UnmarshalMap(uniqueResp.Item, &uniqueRecord); err != nil {
		return AuthenticatedUser{}, fmt.Errorf("decode user unique record: %w", err)
	}

	userResp, err := s.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.usersTable,
		Key: map[string]ddbt.AttributeValue{
			"id": &ddbt.AttributeValueMemberS{Value: uniqueRecord.UserID},
		},
		ConsistentRead: boolPtr(true),
	})
	if err != nil {
		return AuthenticatedUser{}, err
	}
	if len(userResp.Item) == 0 {
		return AuthenticatedUser{}, ErrInvalidCredentials
	}

	var user struct {
		ID           string `dynamodbav:"id"`
		FirstName    string `dynamodbav:"first_name"`
		LastName     string `dynamodbav:"last_name"`
		Email        string `dynamodbav:"email"`
		PasswordHash string `dynamodbav:"password_hash"`
	}
	if err := attributevalue.UnmarshalMap(userResp.Item, &user); err != nil {
		return AuthenticatedUser{}, fmt.Errorf("decode user record: %w", err)
	}

	isValidPassword, err := verifyArgon2idPassword(password, user.PasswordHash)
	if err != nil || !isValidPassword {
		return AuthenticatedUser{}, ErrInvalidCredentials
	}

	return AuthenticatedUser{
		ID:           user.ID,
		FirstName:    user.FirstName,
		LastName:     user.LastName,
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
	}, nil
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

func userUniqueUsernameKey(username string) string {
	return "username#" + username
}

func boolPtr(value bool) *bool {
	return &value
}
