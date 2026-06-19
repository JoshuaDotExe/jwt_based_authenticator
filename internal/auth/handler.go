package auth

import (
	"context"
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

type HandlerService interface {
	AuthenticateUser(ctx context.Context, username, password string) (AuthenticatedUser, error)
	CreateTokens(req TokenInput) (TokenResponse, error)
}

type Handler struct {
	service HandlerService
}

type createTokenRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Aud      string `json:"aud"`
}

func NewHandler(service HandlerService) *Handler {
	return &Handler{service: service}
}

func (h *Handler) PostToken(c *gin.Context) {
	var req createTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	authenticatedUser, err := h.service.AuthenticateUser(c.Request.Context(), req.Username, req.Password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}

		if errors.Is(err, ErrMissingCredentials) {
			c.JSON(http.StatusBadRequest, map[string]string{"error": "username and password are required"})
			return
		}

		log.Printf("authentication error: %v", err)
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	resp, err := h.service.CreateTokens(TokenInput{
		Sub:       authenticatedUser.ID,
		Aud:       req.Aud,
		FirstName: authenticatedUser.FirstName,
		LastName:  authenticatedUser.LastName,
		Email:     authenticatedUser.Email,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create tokens"})
		return
	}

	c.JSON(http.StatusCreated, resp)
}
