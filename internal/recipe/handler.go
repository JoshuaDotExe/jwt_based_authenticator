package recipe

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

var ErrRecipeNotFound = errors.New("recipe not found")
var ErrInvalidRecipeInput = errors.New("invalid recipe input")

const AuthenticatedUserIDKey = "userID"

type Service interface {
	Create(ctx context.Context, ownerID string, input CreateRecipeRequest) (Recipe, error)
	GetByID(ctx context.Context, recipeID string) (Recipe, error)
	GetByOwnerID(ctx context.Context, input GetRecipesByOwnerIDRequest) ([]Recipe, error)
	Update(ctx context.Context, recipeID string, input UpdateRecipeRequest) (Recipe, error)
	Delete(ctx context.Context, recipeID string) error
}

type Handler struct {
	service Service
}

type Ingredient struct {
	Name     string
	Quantity string
	Metric   string
}

type Ingredients struct {
	Count       int
	Ingredients []Ingredient
	Servings    int
}

type Instruction struct {
	StepNumber  int
	Description string
}

type Instructions struct {
	Count        int
	Instructions []Instruction
}

type Recipe struct {
	ID           string
	OwnerID      string
	Title        string
	Tags         []string
	Ingredients  Ingredients
	Instructions Instructions
	CreatedAt    string
	UpdatedAt    string
}

func NewHandler(service Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) GetByOwnerID(c *gin.Context) {
	authenticatedOwnerID := strings.TrimSpace(c.GetString(AuthenticatedUserIDKey))
	if authenticatedOwnerID == "" {
		c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing authenticated user"})
		return
	}

	requestedOwnerID := strings.TrimSpace(c.Param("id"))
	if requestedOwnerID == "" {
		requestedOwnerID = strings.TrimSpace(c.Param("ownerID"))
	}
	if requestedOwnerID != "" && requestedOwnerID != authenticatedOwnerID {
		c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden owner id"})
		return
	}

	recipes, err := h.service.GetByOwnerID(c.Request.Context(), GetRecipesByOwnerIDRequest{OwnerID: authenticatedOwnerID})
	if err != nil {
		if errors.Is(err, ErrInvalidRecipeInput) {
			c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid recipe input"})
			return
		}
		c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	response := getRecipesByOwnerIDResponse{Recipes: make([]getRecipeResponse, 0, len(recipes))}
	for _, recipe := range recipes {
		response.Recipes = append(response.Recipes, newGetRecipeResponse(recipe))
	}

	c.JSON(http.StatusOK, response)
}

func (h *Handler) GetRecipeByID(c *gin.Context) {
	recipeID := strings.TrimSpace(c.Param("id"))
	if recipeID == "" {
		recipeID = strings.TrimSpace(c.Param("recipeID"))
	}
	if recipeID == "" {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "recipe id is required"})
		return
	}

	recipe, err := h.service.GetByID(c.Request.Context(), recipeID)
	if err != nil {
		if errors.Is(err, ErrRecipeNotFound) {
			c.JSON(http.StatusNotFound, map[string]string{"error": "recipe not found"})
			return
		}

		c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, newGetRecipeResponse(recipe))
}

func (h *Handler) CreateRecipe(c *gin.Context) {
	var input CreateRecipeRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	ownerID := strings.TrimSpace(c.GetString(AuthenticatedUserIDKey))
	if ownerID == "" {
		c.JSON(http.StatusUnauthorized, map[string]string{"error": "missing authenticated user"})
		return
	}

	recipe, err := h.service.Create(c.Request.Context(), ownerID, input)
	if err != nil {
		if errors.Is(err, ErrInvalidRecipeInput) {
			c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid recipe input"})
			return
		}

		c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusCreated, newGetRecipeResponse(recipe))
}

func (h *Handler) UpdateRecipe(c *gin.Context) {
	recipeID := strings.TrimSpace(c.Param("id"))
	if recipeID == "" {
		recipeID = strings.TrimSpace(c.Param("recipeID"))
	}
	if recipeID == "" {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "recipe id is required"})
		return
	}

	var input UpdateRecipeRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	recipe, err := h.service.Update(c.Request.Context(), recipeID, input)
	if err != nil {
		if errors.Is(err, ErrRecipeNotFound) {
			c.JSON(http.StatusNotFound, map[string]string{"error": "recipe not found"})
			return
		}
		if errors.Is(err, ErrInvalidRecipeInput) {
			c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid recipe input"})
			return
		}

		c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, newGetRecipeResponse(recipe))
}

func (h *Handler) DeleteRecipe(c *gin.Context) {
	recipeID := strings.TrimSpace(c.Param("id"))
	if recipeID == "" {
		recipeID = strings.TrimSpace(c.Param("recipeID"))
	}
	if recipeID == "" {
		c.JSON(http.StatusBadRequest, map[string]string{"error": "recipe id is required"})
		return
	}

	err := h.service.Delete(c.Request.Context(), recipeID)
	if err != nil {
		if errors.Is(err, ErrRecipeNotFound) {
			c.JSON(http.StatusNotFound, map[string]string{"error": "recipe not found"})
			return
		}

		c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	c.Status(http.StatusNoContent)
}
