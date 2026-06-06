package user

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
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

func (s *postgresService) Create(ctx context.Context, input CreateUserInput) (User, error) {
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

func isUniqueViolation(err error) bool {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		return true
	}

	return false
}
