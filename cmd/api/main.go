package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"jwt_based_authenticator/internal/auth"
	"jwt_based_authenticator/internal/recipe"
	"jwt_based_authenticator/internal/user"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbt "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/gin-gonic/gin"
)

type healthResponse struct {
	Status    string `json:"status"`
	Service   string `json:"service"`
	Timestamp string `json:"timestamp"`
}

type createTokenRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Aud      string `json:"aud"`
}

func main() {
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	awsRegion := strings.TrimSpace(os.Getenv("AWS_REGION"))
	if awsRegion == "" {
		awsRegion = "us-east-1"
	}
	dynamoEndpoint := strings.TrimSpace(os.Getenv("DYNAMODB_ENDPOINT"))
	usersTable := strings.TrimSpace(os.Getenv("USERS_TABLE"))
	if usersTable == "" {
		usersTable = "users"
	}
	userUniquesTable := strings.TrimSpace(os.Getenv("USER_UNIQUES_TABLE"))
	if userUniquesTable == "" {
		userUniquesTable = "user_uniques"
	}
	recipesTable := strings.TrimSpace(os.Getenv("RECIPES_TABLE"))
	if recipesTable == "" {
		recipesTable = "recipes"
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(awsRegion))
	if err != nil {
		log.Fatalf("error: failed to load aws config: %v", err)
	}

	var ddb *dynamodb.Client
	if dynamoEndpoint != "" {
		ddb = dynamodb.NewFromConfig(awsCfg, func(options *dynamodb.Options) {
			options.BaseEndpoint = aws.String(dynamoEndpoint)
		})
	} else {
		ddb = dynamodb.NewFromConfig(awsCfg)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := ensureDynamoTables(ctx, ddb, usersTable, userUniquesTable, recipesTable); err != nil {
		log.Fatalf("error: failed to ensure dynamodb tables: %v", err)
	}

	_, err = ddb.ListTables(ctx, &dynamodb.ListTablesInput{Limit: aws.Int32(1)})
	if err != nil {
		log.Fatalf("error: failed to connect to dynamodb: %v", err)
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatalf("error: JWT_SECRET environment variable not set")
	}

	authService, err := auth.NewService(ddb, usersTable, userUniquesTable, auth.Config{
		Secret:          jwtSecret,
		Issuer:          "auth.local",
		DefaultAudience: "api.local",
		AccessTokenTTL:  15 * time.Minute,
		IDTokenTTL:      15 * time.Minute,
	})
	if err != nil {
		log.Fatalf("error: failed to initialize auth service: %v", err)
	}

	userHandler := user.NewHandler(user.NewDynamoService(ddb, usersTable, userUniquesTable))
	recipeHandler := recipe.NewHandler(recipe.NewDynamoService(ddb, recipesTable))

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, healthResponse{
			Status:    "ok",
			Service:   "jwt-api",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
	})

	router.POST("/token", func(c *gin.Context) {
		var req createTokenRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}

		authenticatedUser, err := authService.AuthenticateUser(c.Request.Context(), req.Username, req.Password)
		if err != nil {
			if errors.Is(err, auth.ErrInvalidCredentials) {
				c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
				return
			}

			if errors.Is(err, auth.ErrMissingCredentials) {
				c.JSON(http.StatusBadRequest, map[string]string{"error": "username and password are required"})
				return
			}

			log.Printf("authentication error: %v", err)
			c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			return
		}

		resp, err := authService.CreateTokens(auth.TokenInput{
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
	})

	router.POST("/user/create", userHandler.PostUser)

	protected := router.Group("")
	protected.Use(auth.NewMiddleware(auth.MiddlewareConfig{
		Secret:         jwtSecret,
		ExpectedIssuer: "auth.local",
	}))
	protected.GET("/me", userHandler.GetMe)
	protected.PATCH("/me", userHandler.UpdateUser)
	protected.POST("/internal/recipe", recipeHandler.CreateRecipe)
	protected.GET("/internal/recipe/:id", recipeHandler.GetRecipeByID)
	protected.PUT("/internal/recipe/:id", recipeHandler.UpdateRecipe)
	protected.DELETE("/internal/recipe/:id", recipeHandler.DeleteRecipe)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("api listening on :%s", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

func ensureDynamoTables(ctx context.Context, ddb *dynamodb.Client, usersTable, userUniquesTable, recipesTable string) error {
	if err := ensureTable(ctx, ddb, usersTable, "id"); err != nil {
		return err
	}

	if err := ensureTable(ctx, ddb, userUniquesTable, "key"); err != nil {
		return err
	}

	if err := ensureTable(ctx, ddb, recipesTable, "id"); err != nil {
		return err
	}

	return nil
}

func ensureTable(ctx context.Context, ddb *dynamodb.Client, tableName, hashKey string) error {
	_, err := ddb.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(tableName)})
	if err == nil {
		return nil
	}

	var notFound *ddbt.ResourceNotFoundException
	if !errors.As(err, &notFound) {
		return err
	}

	_, err = ddb.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: aws.String(tableName),
		AttributeDefinitions: []ddbt.AttributeDefinition{
			{
				AttributeName: aws.String(hashKey),
				AttributeType: ddbt.ScalarAttributeTypeS,
			},
		},
		KeySchema: []ddbt.KeySchemaElement{
			{
				AttributeName: aws.String(hashKey),
				KeyType:       ddbt.KeyTypeHash,
			},
		},
		BillingMode: ddbt.BillingModePayPerRequest,
	})
	if err != nil {
		var inUse *ddbt.ResourceInUseException
		if !errors.As(err, &inUse) {
			return err
		}
	}

	waiter := dynamodb.NewTableExistsWaiter(ddb)
	return waiter.Wait(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(tableName)}, 2*time.Minute)
}
