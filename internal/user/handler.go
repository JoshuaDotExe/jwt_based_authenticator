package user

import (
	"context"
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
)

var ErrUserNotFound = errors.New("user not found")
var ErrUserAlreadyExists = errors.New("user already exists")
var ErrInvalidUserInput = errors.New("invalid user input")

const AuthenticatedUserIDKey = "userID"

type Service interface {
	GetByID(ctx context.Context, userID string) (User, error)
	Create(ctx context.Context, input CreateUserInput) (User, error)
}

type Handler struct {
	service Service
}

type User struct {
	ID        string
	FirstName string
	LastName  string
	Email     string
	Username  string
}

type CreateUserInput struct {
	FirstName string
	LastName  string
	Email     string
	Username  string
	Password  string
}

type getMeResponse struct {
	ID        string `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Username  string `json:"username"`
}

type postUserRequest struct {
	FirstName string `json:"first_name" binding:"required"`
	LastName  string `json:"last_name" binding:"required"`
	Email     string `json:"email" binding:"required,email"`
	Username  string `json:"username" binding:"required"`
	Password  string `json:"password" binding:"required,min=8"`
}

type postUserResponse struct {
	ID        string `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Username  string `json:"username"`
}

func NewHandler(service Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) GetMe(c *gin.Context) {
	userID := strings.TrimSpace(c.GetString(AuthenticatedUserIDKey))
	if userID == "" {
		c.JSON(401, map[string]string{"error": "missing authenticated user"})
		return
	}

	user, err := h.service.GetByID(c.Request.Context(), userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			c.JSON(404, map[string]string{"error": "user not found"})
			return
		}

		c.JSON(500, map[string]string{"error": "internal server error"})
		return
	}

	c.JSON(200, getMeResponse{
		ID:        user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		Username:  user.Username,
	})
}

func (h *Handler) GetUserByID(c *gin.Context) {
	c.JSON(501, map[string]string{"error": "not implemented"})
}

func (h *Handler) PostUser(c *gin.Context) {
	var req postUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, map[string]string{"error": "invalid request body"})
		return
	}

	createdUser, err := h.service.Create(c.Request.Context(), CreateUserInput{
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Email:     req.Email,
		Username:  req.Username,
		Password:  req.Password,
	})
	if err != nil {
		if errors.Is(err, ErrInvalidUserInput) {
			c.JSON(400, map[string]string{"error": "invalid user input"})
			return
		}
		if errors.Is(err, ErrUserAlreadyExists) {
			c.JSON(409, map[string]string{"error": "user already exists"})
			return
		}

		c.JSON(500, map[string]string{"error": "internal server error"})
		return
	}

	c.JSON(201, postUserResponse{
		ID:        createdUser.ID,
		FirstName: createdUser.FirstName,
		LastName:  createdUser.LastName,
		Email:     createdUser.Email,
		Username:  createdUser.Username,
	})
}
