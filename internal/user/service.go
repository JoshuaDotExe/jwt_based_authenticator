package user

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbt "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

type dynamoService struct {
	ddb        *dynamodb.Client
	usersTable string
}

type userRecord struct {
	ID                string `dynamodbav:"id"`
	FirstName         string `dynamodbav:"first_name"`
	LastName          string `dynamodbav:"last_name"`
	Email             string `dynamodbav:"email"`
	Username          string `dynamodbav:"username"`
	PasswordHash      string `dynamodbav:"password_hash"`
	PasswordAlgo      string `dynamodbav:"password_algo"`
	PasswordChangedAt string `dynamodbav:"password_changed_at"`
	CreatedAt         string `dynamodbav:"created_at"`
	UpdatedAt         string `dynamodbav:"updated_at"`
}

func NewDynamoService(ddb *dynamodb.Client, usersTable string) Service {
	return &dynamoService{
		ddb:        ddb,
		usersTable: strings.TrimSpace(usersTable),
	}
}

func (s *dynamoService) GetByID(ctx context.Context, userID string) (User, error) {
	record, err := s.getUserRecordByID(ctx, userID)
	if err != nil {
		return User{}, err
	}

	return User{
		ID:        record.ID,
		FirstName: record.FirstName,
		LastName:  record.LastName,
		Email:     record.Email,
		Username:  record.Username,
	}, nil

}

func (s *dynamoService) getUserRecordByID(ctx context.Context, userID string) (userRecord, error) {
	resp, err := s.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.usersTable,
		Key: map[string]ddbt.AttributeValue{
			"id": &ddbt.AttributeValueMemberS{Value: userID},
		},
		ConsistentRead: boolPtr(true),
	})
	if err != nil {
		return userRecord{}, err
	}

	if len(resp.Item) == 0 {
		return userRecord{}, ErrUserNotFound
	}

	var record userRecord
	if err := attributevalue.UnmarshalMap(resp.Item, &record); err != nil {
		return userRecord{}, err
	}

	return record, nil
}

func (s *dynamoService) Create(ctx context.Context, input CreateUserRequest) (User, error) {
	newUser := User{
		ID:        uuid.NewString(),
		FirstName: strings.TrimSpace(input.FirstName),
		LastName:  strings.TrimSpace(input.LastName),
		Email:     strings.ToLower(strings.TrimSpace(input.Email)),
		Username:  strings.TrimSpace(input.Username),
	}
	password := input.Password

	if newUser.FirstName == "" || newUser.LastName == "" || newUser.Email == "" || newUser.Username == "" || len(password) < 8 {
		return User{}, ErrInvalidUserInput
	}

	passwordHash, err := hashArgon2idPassword(password)
	if err != nil {
		return User{}, err
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	record := userRecord{
		ID:                newUser.ID,
		FirstName:         newUser.FirstName,
		LastName:          newUser.LastName,
		Email:             newUser.Email,
		Username:          newUser.Username,
		PasswordHash:      passwordHash,
		PasswordAlgo:      "argon2id",
		PasswordChangedAt: now,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	userItem, err := attributevalue.MarshalMap(record)
	if err != nil {
		return User{}, err
	}

	_, err = s.ddb.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           &s.usersTable,
		Item:                userItem,
		ConditionExpression: stringPtr("attribute_not_exists(id)"),
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return User{}, ErrUserAlreadyExists
		}
		return User{}, err
	}

	return newUser, nil
}

func (s *dynamoService) UpdateName(ctx context.Context, userID string, input UpdateUserNameRequest) (User, error) {
	firstName := strings.TrimSpace(input.FirstName)
	lastName := strings.TrimSpace(input.LastName)
	if firstName == "" || lastName == "" {
		return User{}, ErrInvalidUserInput
	}

	resp, err := s.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &s.usersTable,
		Key: map[string]ddbt.AttributeValue{
			"id": &ddbt.AttributeValueMemberS{Value: userID},
		},
		ConditionExpression: stringPtr("attribute_exists(id)"),
		UpdateExpression:    stringPtr("SET first_name = :first_name, last_name = :last_name, updated_at = :updated_at"),
		ExpressionAttributeValues: map[string]ddbt.AttributeValue{
			":first_name": &ddbt.AttributeValueMemberS{Value: firstName},
			":last_name":  &ddbt.AttributeValueMemberS{Value: lastName},
			":updated_at": &ddbt.AttributeValueMemberS{Value: time.Now().UTC().Format(time.RFC3339Nano)},
		},
		ReturnValues: ddbt.ReturnValueAllNew,
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return User{}, ErrUserNotFound
		}
		return User{}, err
	}

	var updated userRecord
	if err := attributevalue.UnmarshalMap(resp.Attributes, &updated); err != nil {
		return User{}, err
	}

	return User{
		ID:        updated.ID,
		FirstName: updated.FirstName,
		LastName:  updated.LastName,
		Email:     updated.Email,
		Username:  updated.Username,
	}, nil
}

func (s *dynamoService) UpdateEmail(ctx context.Context, userID string, input UpdateUserEmailRequest) (User, error) {
	email := strings.ToLower(strings.TrimSpace(input.Email))
	if email == "" {
		return User{}, ErrInvalidUserInput
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &s.usersTable,
		Key: map[string]ddbt.AttributeValue{
			"id": &ddbt.AttributeValueMemberS{Value: userID},
		},
		ConditionExpression: stringPtr("attribute_exists(id)"),
		UpdateExpression:    stringPtr("SET email = :email, updated_at = :updated_at"),
		ExpressionAttributeValues: map[string]ddbt.AttributeValue{
			":email":      &ddbt.AttributeValueMemberS{Value: email},
			":updated_at": &ddbt.AttributeValueMemberS{Value: now},
		},
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return User{}, ErrUserNotFound
		}
		return User{}, err
	}

	return s.GetByID(ctx, userID)
}

func (s *dynamoService) UpdateUsername(ctx context.Context, userID string, input UpdateUserUsernameRequest) (User, error) {
	username := strings.TrimSpace(input.Username)
	if username == "" {
		return User{}, ErrInvalidUserInput
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &s.usersTable,
		Key: map[string]ddbt.AttributeValue{
			"id": &ddbt.AttributeValueMemberS{Value: userID},
		},
		ConditionExpression: stringPtr("attribute_exists(id)"),
		UpdateExpression:    stringPtr("SET username = :username, updated_at = :updated_at"),
		ExpressionAttributeValues: map[string]ddbt.AttributeValue{
			":username":   &ddbt.AttributeValueMemberS{Value: username},
			":updated_at": &ddbt.AttributeValueMemberS{Value: now},
		},
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return User{}, ErrUserNotFound
		}
		return User{}, err
	}

	return s.GetByID(ctx, userID)
}

func (s *dynamoService) UpdatePassword(ctx context.Context, userID string, input UpdateUserPasswordRequest) (User, error) {
	currentPassword := input.CurrentPassword
	newPassword := input.NewPassword
	if currentPassword == "" || len(newPassword) < 8 {
		return User{}, ErrInvalidUserInput
	}

	record, err := s.getUserRecordByID(ctx, userID)
	if err != nil {
		return User{}, err
	}

	isValid, err := verifyArgon2idPassword(currentPassword, record.PasswordHash)
	if err != nil {
		return User{}, err
	}
	if !isValid {
		return User{}, ErrInvalidUserInput
	}

	newHash, err := hashArgon2idPassword(newPassword)
	if err != nil {
		return User{}, err
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &s.usersTable,
		Key: map[string]ddbt.AttributeValue{
			"id": &ddbt.AttributeValueMemberS{Value: userID},
		},
		ConditionExpression: stringPtr("attribute_exists(id)"),
		UpdateExpression:    stringPtr("SET password_hash = :password_hash, password_algo = :password_algo, password_changed_at = :password_changed_at, updated_at = :updated_at"),
		ExpressionAttributeValues: map[string]ddbt.AttributeValue{
			":password_hash":       &ddbt.AttributeValueMemberS{Value: newHash},
			":password_algo":       &ddbt.AttributeValueMemberS{Value: "argon2id"},
			":password_changed_at": &ddbt.AttributeValueMemberS{Value: now},
			":updated_at":          &ddbt.AttributeValueMemberS{Value: now},
		},
	})
	if err != nil {
		if isConditionalCheckFailed(err) {
			return User{}, ErrUserNotFound
		}
		return User{}, err
	}

	return s.GetByID(ctx, userID)
}

func hashArgon2idPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	timeCost := uint32(3)
	memory := uint32(64 * 1024)
	threads := uint8(2)
	keyLen := uint32(32)

	hash := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, keyLen)
	encodedHash := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		memory,
		timeCost,
		threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return encodedHash, nil
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

func isConditionalCheckFailed(err error) bool {
	var ccf *ddbt.ConditionalCheckFailedException
	if errors.As(err, &ccf) {
		return true
	}

	return false
}

func stringPtr(value string) *string {
	return &value
}

func boolPtr(value bool) *bool {
	return &value
}
