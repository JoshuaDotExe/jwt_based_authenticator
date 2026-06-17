package recipe

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbt "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/google/uuid"
)

type dynamoService struct {
	ddb         *dynamodb.Client
	recipeTable string
}

type recipeRecord struct {
	ID           string       `dynamodbav:"id"`
	OwnerID      string       `dynamodbav:"owner_id"`
	Title        string       `dynamodbav:"title"`
	Ingredients  Ingredients  `dynamodbav:"ingredients"`
	Instructions Instructions `dynamodbav:"instructions"`
	CreatedAt    string       `dynamodbav:"created_at"`
	UpdatedAt    string       `dynamodbav:"updated_at"`
}

func NewDynamoService(ddb *dynamodb.Client, recipeTable string) Service {
	return &dynamoService{
		ddb:         ddb,
		recipeTable: recipeTable,
	}
}

func (s *dynamoService) Create(ctx context.Context, ownerID string, input CreateRecipeRequest) (Recipe, error) {
	ownerID = strings.TrimSpace(ownerID)
	title := strings.TrimSpace(input.Title)
	if ownerID == "" || title == "" {
		return Recipe{}, ErrInvalidRecipeInput
	}

	now := time.Now().UTC().Format(time.RFC3339)
	newRecipe := recipeRecord{
		ID:           uuid.NewString(),
		OwnerID:      ownerID,
		Title:        title,
		Ingredients:  input.Ingredients,
		Instructions: input.Instructions,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	recipeItem, err := attributevalue.MarshalMap(newRecipe)
	if err != nil {
		return Recipe{}, err
	}

	_, err = s.ddb.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &s.recipeTable,
		Item:      recipeItem,
	})
	if err != nil {
		return Recipe{}, err
	}

	return Recipe{
		ID:           newRecipe.ID,
		OwnerID:      newRecipe.OwnerID,
		Title:        newRecipe.Title,
		Ingredients:  newRecipe.Ingredients,
		Instructions: newRecipe.Instructions,
		CreatedAt:    newRecipe.CreatedAt,
		UpdatedAt:    newRecipe.UpdatedAt,
	}, nil
}

func (s *dynamoService) GetByID(ctx context.Context, recipeID string) (Recipe, error) {
	resp, err := s.ddb.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.recipeTable,
		Key: map[string]ddbt.AttributeValue{
			"id": &ddbt.AttributeValueMemberS{Value: recipeID},
		},
	})
	if err != nil {
		return Recipe{}, err
	}

	if resp.Item == nil {
		return Recipe{}, ErrRecipeNotFound
	}

	var recipeRecord recipeRecord
	err = attributevalue.UnmarshalMap(resp.Item, &recipeRecord)
	if err != nil {
		return Recipe{}, err
	}

	return Recipe{
		ID:           recipeRecord.ID,
		OwnerID:      recipeRecord.OwnerID,
		Title:        recipeRecord.Title,
		Ingredients:  recipeRecord.Ingredients,
		Instructions: recipeRecord.Instructions,
		CreatedAt:    recipeRecord.CreatedAt,
		UpdatedAt:    recipeRecord.UpdatedAt,
	}, nil
}

func (s *dynamoService) Update(ctx context.Context, recipeID string, input UpdateRecipeRequest) (Recipe, error) {
	recipeID = strings.TrimSpace(recipeID)
	title := strings.TrimSpace(input.Title)
	if recipeID == "" || title == "" {
		return Recipe{}, ErrInvalidRecipeInput
	}

	now := time.Now().UTC().Format(time.RFC3339)
	ingredientsAV, err := attributevalue.Marshal(input.Ingredients)
	if err != nil {
		return Recipe{}, err
	}

	instructionsAV, err := attributevalue.Marshal(input.Instructions)
	if err != nil {
		return Recipe{}, err
	}

	resp, err := s.ddb.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: &s.recipeTable,
		Key: map[string]ddbt.AttributeValue{
			"id": &ddbt.AttributeValueMemberS{Value: recipeID},
		},
		ConditionExpression: awsString("attribute_exists(id)"),
		UpdateExpression:    awsString("SET title = :title, ingredients = :ingredients, instructions = :instructions, updated_at = :updated_at"),
		ExpressionAttributeValues: map[string]ddbt.AttributeValue{
			":title":        &ddbt.AttributeValueMemberS{Value: title},
			":ingredients":  ingredientsAV,
			":instructions": instructionsAV,
			":updated_at":   &ddbt.AttributeValueMemberS{Value: now},
		},
		ReturnValues: ddbt.ReturnValueAllNew,
	})
	if err != nil {
		var condErr *ddbt.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return Recipe{}, ErrRecipeNotFound
		}
		return Recipe{}, err
	}

	var updated recipeRecord
	if err := attributevalue.UnmarshalMap(resp.Attributes, &updated); err != nil {
		return Recipe{}, err
	}

	return Recipe{
		ID:           updated.ID,
		OwnerID:      updated.OwnerID,
		Title:        updated.Title,
		Ingredients:  updated.Ingredients,
		Instructions: updated.Instructions,
		CreatedAt:    updated.CreatedAt,
		UpdatedAt:    updated.UpdatedAt,
	}, nil
}

func (s *dynamoService) Delete(ctx context.Context, recipeID string) error {
	recipeID = strings.TrimSpace(recipeID)
	if recipeID == "" {
		return ErrInvalidRecipeInput
	}

	_, err := s.ddb.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &s.recipeTable,
		Key: map[string]ddbt.AttributeValue{
			"id": &ddbt.AttributeValueMemberS{Value: recipeID},
		},
		ConditionExpression: awsString("attribute_exists(id)"),
	})
	if err != nil {
		var condErr *ddbt.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return ErrRecipeNotFound
		}
		return err
	}

	return nil
}

func awsString(value string) *string {
	return &value
}
