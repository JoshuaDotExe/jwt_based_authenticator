package user

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"golang.org/x/crypto/argon2"
)

type postgresService struct {
	db *sql.DB
}

func NewPostgresService(db *sql.DB) Service {
	return &postgresService{db: db}
}

func (s *postgresService) GetByID(ctx context.Context, userID string) (User, error) {
	var result User

	err := s.db.QueryRowContext(
		ctx,
		"SELECT id::text, first_name, last_name, email, username FROM users WHERE id = $1",
		userID,
	).Scan(&result.ID, &result.FirstName, &result.LastName, &result.Email, &result.Username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrUserNotFound
		}
		return User{}, err
	}

	return result, nil
}

func (s *postgresService) Create(ctx context.Context, input CreateUserRequest) (User, error) {
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

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(
		ctx,
		"INSERT INTO users (id, first_name, last_name, email, username) VALUES ($1, $2, $3, $4, $5)",
		newUser.ID,
		newUser.FirstName,
		newUser.LastName,
		newUser.Email,
		newUser.Username,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return User{}, ErrUserAlreadyExists
		}
		return User{}, err
	}

	_, err = tx.ExecContext(
		ctx,
		"INSERT INTO user_credentials (user_id, password_hash, password_algo) VALUES ($1, $2, $3)",
		newUser.ID,
		passwordHash,
		"argon2id",
	)
	if err != nil {
		if isUniqueViolation(err) {
			return User{}, ErrUserAlreadyExists
		}
		return User{}, err
	}

	if err := tx.Commit(); err != nil {
		return User{}, err
	}

	return newUser, nil
}

func (s *postgresService) UpdateName(ctx context.Context, userID string, input UpdateUserNameRequest) (User, error) {
	firstName := strings.TrimSpace(input.FirstName)
	lastName := strings.TrimSpace(input.LastName)
	if firstName == "" || lastName == "" {
		return User{}, ErrInvalidUserInput
	}

	var updated User
	err := s.db.QueryRowContext(
		ctx,
		"UPDATE users SET first_name = $2, last_name = $3, updated_at = NOW() WHERE id = $1 RETURNING id::text, first_name, last_name, email, username",
		userID,
		firstName,
		lastName,
	).Scan(&updated.ID, &updated.FirstName, &updated.LastName, &updated.Email, &updated.Username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrUserNotFound
		}
		return User{}, err
	}

	return updated, nil
}

func (s *postgresService) UpdateEmail(ctx context.Context, userID string, input UpdateUserEmailRequest) (User, error) {
	email := strings.ToLower(strings.TrimSpace(input.Email))
	if email == "" {
		return User{}, ErrInvalidUserInput
	}

	var updated User
	err := s.db.QueryRowContext(
		ctx,
		"UPDATE users SET email = $2, updated_at = NOW() WHERE id = $1 RETURNING id::text, first_name, last_name, email, username",
		userID,
		email,
	).Scan(&updated.ID, &updated.FirstName, &updated.LastName, &updated.Email, &updated.Username)
	if err != nil {
		if isUniqueViolation(err) {
			return User{}, ErrUserAlreadyExists
		}
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrUserNotFound
		}
		return User{}, err
	}

	return updated, nil
}

func (s *postgresService) UpdateUsername(ctx context.Context, userID string, input UpdateUserUsernameRequest) (User, error) {
	username := strings.TrimSpace(input.Username)
	if username == "" {
		return User{}, ErrInvalidUserInput
	}

	var updated User
	err := s.db.QueryRowContext(
		ctx,
		"UPDATE users SET username = $2, updated_at = NOW() WHERE id = $1 RETURNING id::text, first_name, last_name, email, username",
		userID,
		username,
	).Scan(&updated.ID, &updated.FirstName, &updated.LastName, &updated.Email, &updated.Username)
	if err != nil {
		if isUniqueViolation(err) {
			return User{}, ErrUserAlreadyExists
		}
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrUserNotFound
		}
		return User{}, err
	}

	return updated, nil
}

func (s *postgresService) UpdatePassword(ctx context.Context, userID string, input UpdateUserPasswordRequest) (User, error) {
	currentPassword := input.CurrentPassword
	newPassword := input.NewPassword
	if currentPassword == "" || len(newPassword) < 8 {
		return User{}, ErrInvalidUserInput
	}

	var encodedHash string
	err := s.db.QueryRowContext(
		ctx,
		"SELECT password_hash FROM user_credentials WHERE user_id = $1",
		userID,
	).Scan(&encodedHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrUserNotFound
		}
		return User{}, err
	}

	isValid, err := verifyArgon2idPassword(currentPassword, encodedHash)
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

	_, err = s.db.ExecContext(
		ctx,
		"UPDATE user_credentials SET password_hash = $2, password_algo = $3, password_changed_at = NOW() WHERE user_id = $1",
		userID,
		newHash,
		"argon2id",
	)
	if err != nil {
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

func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		return true
	}

	return false
}
